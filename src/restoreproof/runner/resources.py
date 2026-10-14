"""Managed-resource tracking and cleanup.

Resources are recorded in their own committed transaction *before* they are created, so a crash between
"create" and "record" cannot leave an untracked container or directory. Cleanup is bounded, retried, and its
outcome is stored independently of the recovery result.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from sqlalchemy import select

from restoreproof.config import get_settings
from restoreproof.db.models import JobAttempt, ManagedResource, utcnow
from restoreproof.db.session import session_scope
from restoreproof.evidence.sanitization import truncate
from restoreproof.jobs.state_machine import CleanupStatus
from restoreproof.runner import docker as dk
from restoreproof.security.paths import safe_remove_run_dir

log = logging.getLogger(__name__)
CLEANUP_ORDER = {"container": 0, "network": 1, "directory": 2}
MAX_CLEANUP_TRIES = 3


def register_resource(attempt_id: str, resource_type: str, external_id: str) -> str:
    with session_scope() as s:
        existing = s.scalar(select(ManagedResource).where(
            ManagedResource.attempt_id == attempt_id, ManagedResource.external_id == external_id,
            ManagedResource.resource_type == resource_type))
        if existing:
            return existing.id
        row = ManagedResource(attempt_id=attempt_id, resource_type=resource_type, external_id=external_id)
        s.add(row)
        s.flush()
        return row.id


def _remove(resource_type: str, external_id: str, attempt_id: str) -> None:
    if resource_type == "container":
        dk.remove_container(external_id)
    elif resource_type == "network":
        dk.remove_network(external_id)
    elif resource_type == "directory":
        safe_remove_run_dir(get_settings().temp_root, Path(external_id), attempt_id)
    else:
        raise ValueError(f"unknown resource type {resource_type}")


def cleanup_attempt(attempt_id: str, *, tries: int = MAX_CLEANUP_TRIES, backoff: float = 1.0) -> tuple[str, list[dict]]:
    """Remove every pending/failed resource of an attempt. Returns (cleanup_status, problems)."""
    with session_scope() as s:
        rows = s.scalars(select(ManagedResource).where(
            ManagedResource.attempt_id == attempt_id,
            ManagedResource.cleanup_status.in_([CleanupStatus.PENDING, CleanupStatus.FAILED]))).all()
        todo = sorted(((r.id, r.resource_type, r.external_id) for r in rows), key=lambda t: CLEANUP_ORDER[t[1]])
    problems: list[dict] = []
    for rid, rtype, ext in todo:
        err: str | None = None
        for i in range(tries):
            try:
                _remove(rtype, ext, attempt_id)
                err = None
                break
            except Exception as exc:  # noqa: BLE001 - every failure is recorded, none is fatal to the loop
                err = truncate(f"{type(exc).__name__}: {exc}", 1000)
                if getattr(exc, "code", "") == "ownership_check_failed":
                    break  # retrying will not change ownership
                time.sleep(backoff * (2**i))
        with session_scope() as s:
            row = s.get(ManagedResource, rid)
            row.cleanup_attempts += 1
            if err is None:
                row.cleanup_status, row.cleaned_at, row.cleanup_error = CleanupStatus.COMPLETED, utcnow(), None
            else:
                row.cleanup_status, row.cleanup_error = CleanupStatus.FAILED, err
                problems.append({"resource_type": rtype, "external_id": ext, "error": err})
    with session_scope() as s:
        total = s.scalars(select(ManagedResource.id).where(ManagedResource.attempt_id == attempt_id)).all()
    if problems:
        return CleanupStatus.FAILED, problems
    return (CleanupStatus.COMPLETED if total else CleanupStatus.NOT_REQUIRED), []


def reconcile_orphans() -> list[dict]:
    """After a restart: clean resources of finished/interrupted attempts, and report labelled Docker objects
    that RestoreProof has no record of (they are removed only if their attempt is known and finished)."""
    report: list[dict] = []
    with session_scope() as s:
        attempt_ids = s.scalars(
            select(ManagedResource.attempt_id).join(JobAttempt, JobAttempt.id == ManagedResource.attempt_id)
            .where(ManagedResource.cleanup_status.in_([CleanupStatus.PENDING, CleanupStatus.FAILED]),
                   JobAttempt.status != "running").distinct()).all()
    for aid in attempt_ids:
        status, problems = cleanup_attempt(aid, tries=2, backoff=0.5)
        with session_scope() as s:
            att = s.get(JobAttempt, aid)
            if att and att.cleanup_status != status:
                att.cleanup_status = status
        report.append({"attempt_id": aid, "cleanup_status": status, "problems": problems})
    ok, _ = dk.docker_available(timeout=5)
    if ok:
        with session_scope() as s:
            running = set(s.scalars(select(JobAttempt.id).where(JobAttempt.status == "running")).all())
            known = set(s.scalars(select(JobAttempt.id)).all())
        for kind in ("container", "network"):
            for name, aid in dk.list_managed(kind):
                if aid in running:
                    continue
                if aid in known:
                    register_resource(aid, kind, name)
                    status, problems = cleanup_attempt(aid, tries=2, backoff=0.5)
                    report.append({"attempt_id": aid, "orphan": name, "cleanup_status": status})
                else:
                    report.append({"orphan": name, "attempt_id": aid, "action": "left in place: unknown attempt"})
    return report

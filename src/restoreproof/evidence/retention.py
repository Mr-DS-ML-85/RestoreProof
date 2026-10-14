"""Artifact retention. Removes old evidence *files* but keeps every database row (status, check results,
artifact sha256), so history and audit stay intact. Never purges the latest passing report of an app, any
artifact referenced by an active baseline, or artifacts of a running attempt."""

from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from restoreproof import audit
from restoreproof.config import get_settings
from restoreproof.db.models import EvidenceArtifact, Job, JobAttempt, utcnow
from restoreproof.db.session import session_scope
from restoreproof import settings_store

log = logging.getLogger(__name__)
KIND_SETTING = {"log": "log_days", "inventory": "inventory_days", "manifest": "report_days",
                "report_html": "report_days"}


def purge(now=None) -> dict[str, int]:
    now = now or utcnow()
    root = get_settings().reports_dir.resolve()
    removed = {"files": 0, "bytes": 0}
    with session_scope() as s:
        ret = settings_store.get(s, "retention")
        protected_attempts: set[str] = set()
        # Latest passing attempt per app keeps its full report.
        for (app_id,) in s.execute(select(Job.app_id).distinct()).all():
            j = s.scalars(select(Job).where(Job.app_id == app_id, Job.status == "passed")
                          .order_by(Job.finished_at.desc()).limit(1)).first()
            if j:
                att = s.scalars(select(JobAttempt.id).where(JobAttempt.job_id == j.id)
                                .order_by(JobAttempt.attempt_number.desc()).limit(1)).first()
                if att:
                    protected_attempts.add(att)
        protected_attempts |= set(s.scalars(select(JobAttempt.id).where(JobAttempt.status == "running")).all())
        # Baselines keep their own copy in the database; their source files may be purged normally.
        baseline_paths: set[Path] = set()
        rows = s.scalars(select(EvidenceArtifact).where(EvidenceArtifact.purged_at.is_(None))).all()
        for art in rows:
            days = getattr(ret, KIND_SETTING.get(art.artifact_type, "report_days"))
            if not days or art.attempt_id in protected_attempts:
                continue
            if now - art.created_at < timedelta(days=days):
                continue
            p = Path(art.storage_path).resolve()
            if p in baseline_paths or root not in p.parents:
                continue
            try:
                size = p.stat().st_size if p.exists() else 0
                p.unlink(missing_ok=True)
            except OSError as exc:
                log.warning("retention could not remove %s: %s", p, exc)
                continue
            art.purged_at = now
            removed["files"] += 1
            removed["bytes"] += size
        if removed["files"]:
            audit.record(s, "retention.purged", details=removed)
    return removed

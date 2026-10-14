"""Deleting applications, sources/destinations and backup plans without corrupting history.

Rules:
- Nothing that is running (test or backup) can be deleted; cancel it first.
- Deleting an application either keeps its test history (row hidden, name freed, results stay readable) or
  removes everything, including report files.
- A source/destination still used by an application or backup plan cannot be deleted; the caller gets the list.
- The *backup data* inside a repository is never touched by any delete.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.config import get_settings
from restoreproof.db.models import (
    BackupPlan,
    BackupRun,
    BackupSource,
    Baseline,
    CheckResult,
    EvidenceArtifact,
    Job,
    JobAttempt,
    ManagedResource,
    Policy,
    ProtectedApp,
    RecoveryPoint,
    StoredSecret,
    TestDefinitionVersion,
    User,
    utcnow,
)


class Blocked(Exception):
    def __init__(self, code: str, message: str, details: object = None):
        super().__init__(message)
        self.code, self.details = code, details


def _remove_file(path: str | None) -> None:
    if not path:
        return
    p = Path(path).resolve()
    root = get_settings().reports_dir.resolve()
    if root in p.parents and p.is_file():  # only ever delete files RestoreProof wrote under its reports dir
        p.unlink()


def delete_app(s: Session, app: ProtectedApp, *, keep_history: bool, actor: User | None) -> dict:
    active = s.scalar(select(Job.id).where(Job.app_id == app.id, Job.status.in_(["queued", "running"])))
    if active:
        raise Blocked("job_active", "a test of this application is queued or running; cancel it first", {"job_id": active})
    job_ids = s.scalars(select(Job.id).where(Job.app_id == app.id)).all()
    attempt_ids = s.scalars(select(JobAttempt.id).where(JobAttempt.job_id.in_(job_ids))).all() if job_ids else []
    pending = s.scalar(select(func.count()).select_from(ManagedResource).where(
        ManagedResource.attempt_id.in_(attempt_ids), ManagedResource.cleanup_status.in_(["pending", "cleanup_failed"]))) \
        if attempt_ids else 0
    if pending and not keep_history:
        raise Blocked("cleanup_pending", "some temporary resources of this app's tests still need cleanup; "
                                         "run `restoreproof reconcile` first, or keep the history")
    for plan in s.scalars(select(BackupPlan)).all():
        if app.id in (plan.verify_app_ids or []):
            plan.verify_app_ids = [a for a in plan.verify_app_ids if a != app.id]
    s.execute(delete(Policy).where(Policy.app_id == app.id))
    name = app.name
    if keep_history and job_ids:
        app.deleted_at = utcnow()
        app.archived = True
        app.name = f"{name}~deleted-{uuid.uuid4().hex[:6]}"  # frees the name for a new app
        result = {"deleted": True, "history_kept": True, "runs": len(job_ids)}
    else:
        for art in s.scalars(select(EvidenceArtifact).where(EvidenceArtifact.attempt_id.in_(attempt_ids))).all() \
                if attempt_ids else []:
            _remove_file(art.storage_path)
        if attempt_ids:
            for model in (CheckResult, ManagedResource, EvidenceArtifact):
                s.execute(delete(model).where(model.attempt_id.in_(attempt_ids)))
        s.execute(delete(Baseline).where(Baseline.app_id == app.id))
        if attempt_ids:
            s.execute(delete(JobAttempt).where(JobAttempt.id.in_(attempt_ids)))
        if job_ids:
            s.execute(delete(Job).where(Job.id.in_(job_ids)))
        s.execute(delete(TestDefinitionVersion).where(TestDefinitionVersion.app_id == app.id))
        s.delete(app)
        result = {"deleted": True, "history_kept": False, "runs": len(job_ids)}
    audit.record(s, "app.deleted", actor=actor, target_type="app", target_id=app.id,
                 details={"name": name, **result})
    return result


def source_dependents(s: Session, src: BackupSource) -> dict:
    apps = s.scalars(select(ProtectedApp).where(ProtectedApp.source_id == src.id,
                                                ProtectedApp.deleted_at.is_(None))).all()
    plans = [p for p in s.scalars(select(BackupPlan)).all() if src.id in (p.destination_ids or [])]
    return {"apps": [{"id": a.id, "name": a.name} for a in apps],
            "backup_plans": [{"id": p.id, "name": p.name} for p in plans]}


def delete_source(s: Session, src: BackupSource, *, actor: User | None) -> dict:
    deps = source_dependents(s, src)
    if deps["apps"] or deps["backup_plans"]:
        names = [a["name"] for a in deps["apps"]] + [f"backup plan {p['name']}" for p in deps["backup_plans"]]
        raise Blocked("in_use", f"still used by: {', '.join(names)}. Delete or change those first.", deps)
    running = s.scalar(select(BackupRun.id).where(BackupRun.destination_id == src.id,
                                                  BackupRun.status.in_(["queued", "running"])))
    if running:
        raise Blocked("backup_active", "a backup to this destination is running")
    # Apps deleted earlier with "keep history" may still point here; detach them.
    for a in s.scalars(select(ProtectedApp).where(ProtectedApp.source_id == src.id)).all():
        a.source_id = None
    s.execute(delete(RecoveryPoint).where(RecoveryPoint.source_id == src.id))
    secret_ref, name = src.secret_ref, src.name
    s.delete(src)
    s.flush()
    if secret_ref:
        s.execute(delete(StoredSecret).where(StoredSecret.id == secret_ref))
    audit.record(s, "source.deleted", actor=actor, target_type="source", target_id=src.id,
                 details={"name": name, "note": "repository data was not touched"})
    return {"deleted": True}


def delete_plan(s: Session, plan: BackupPlan, *, actor: User | None) -> dict:
    active = s.scalar(select(BackupRun.id).where(BackupRun.plan_id == plan.id,
                                                 BackupRun.status.in_(["queued", "running"])))
    if active:
        raise Blocked("backup_active", "this plan is backing up right now; wait for it to finish")
    runs = s.scalars(select(BackupRun).where(BackupRun.plan_id == plan.id)).all()
    for r in runs:
        _remove_file(r.log_path)
    n_runs = len(runs)
    # Explicit order: run rows first (they reference the plan), then the plan.
    s.execute(delete(BackupRun).where(BackupRun.plan_id == plan.id))
    name = plan.name
    s.delete(plan)
    s.flush()
    audit.record(s, "backup_plan.deleted", actor=actor, target_type="backup_plan", target_id=plan.id,
                 details={"name": name, "runs": n_runs, "note": "snapshots already made were not touched"})
    return {"deleted": True, "runs": n_runs}

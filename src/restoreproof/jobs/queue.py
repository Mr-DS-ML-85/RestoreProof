"""Database-backed job queue.

- `jobs.active_lock` (unique, = app_id while non-terminal) prevents overlapping runs per application.
- `jobs.idempotency_key` (unique) makes duplicate requests / scheduler ticks return the existing job.
- Claiming is a compare-and-swap UPDATE, safe across processes on both PostgreSQL and SQLite.
- Every attempt is its own row; a retry never overwrites the evidence of an earlier attempt.
"""

from __future__ import annotations

import os
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.config import get_settings
from restoreproof.db.models import Job, JobAttempt, ProtectedApp, User, WorkerRecord, utcnow
from restoreproof.db.session import session_scope
from restoreproof.jobs.state_machine import (
    TERMINAL_JOB,
    AttemptStatus,
    JobStatus,
    assert_attempt_transition,
    assert_job_transition,
)


class ActiveJobExists(Exception):
    def __init__(self, job_id: str):
        super().__init__(f"application already has an active job {job_id}")
        self.job_id = job_id


def enqueue(session: Session, app: ProtectedApp, *, trigger: str, requested_by: User | None = None,
            idempotency_key: str | None = None, pinned_recovery_point: str | None = None) -> tuple[Job, bool]:
    """Returns (job, created). Commits nothing; the caller's transaction decides."""
    if idempotency_key:
        existing = session.scalar(select(Job).where(Job.idempotency_key == idempotency_key))
        if existing:
            if existing.app_id != app.id:
                raise ValueError("idempotency key was already used for a different application")
            return existing, False
    job = Job(app_id=app.id, status=JobStatus.QUEUED, trigger=trigger,
              requested_by=requested_by.id if requested_by else None, idempotency_key=idempotency_key,
              active_lock=app.id, definition_version=app.definition_version,
              definition_sha256=app.definition_sha256, pinned_recovery_point=pinned_recovery_point)
    try:
        with session.begin_nested():
            session.add(job)
            session.flush()
    except IntegrityError:
        if idempotency_key:
            existing = session.scalar(select(Job).where(Job.idempotency_key == idempotency_key))
            if existing:
                return existing, False
        active = session.scalar(select(Job).where(Job.active_lock == app.id))
        raise ActiveJobExists(active.id if active else "unknown") from None
    audit.record(session, "job.queued", actor=requested_by, target_type="job", target_id=job.id,
                 details={"app_id": app.id, "trigger": trigger})
    return job, True


def in_window(window: str, tz: str, now) -> bool:
    if not window:
        return True
    from zoneinfo import ZoneInfo
    start, end = window.split("-")
    t = now.astimezone(ZoneInfo(tz)).strftime("%H:%M")
    return start <= t < end if start <= end else (t >= start or t < end)


def host_load() -> tuple[float, int]:
    try:
        return os.getloadavg()[0], os.cpu_count() or 1
    except OSError:
        return 0.0, os.cpu_count() or 1


def _set_note(s: Session, worker_id: str, note: str | None) -> None:
    w = s.get(WorkerRecord, worker_id)
    if w is not None and w.status_note != note:
        w.status_note = note


def claim_next(worker_id: str) -> tuple[str, str] | None:
    """Atomically take the oldest runnable job and open a new attempt. Returns (job_id, attempt_id)."""
    from restoreproof import settings_store

    settings = get_settings()
    now = utcnow()
    with session_scope() as s:
        wl = settings_store.get(s, "workload")
        load, cpus = host_load()
        if wl.max_load_per_cpu and load > wl.max_load_per_cpu * cpus:
            _set_note(s, worker_id, f"waiting: host busy (load {load:.1f} on {cpus} CPUs, limit "
                                    f"{wl.max_load_per_cpu * cpus:.1f})")
            return None
        window_open = in_window(wl.maintenance_window, wl.timezone, now)
        _set_note(s, worker_id, None if window_open else
                  f"scheduled tests wait for the maintenance window {wl.maintenance_window} ({wl.timezone})")
        running = s.scalar(select(func.count()).select_from(JobAttempt)
                           .where(JobAttempt.status == AttemptStatus.RUNNING)) or 0
        if running >= settings.max_concurrent_jobs:
            return None
        q = select(Job.id).where(Job.status == JobStatus.QUEUED,
                                 (Job.not_before.is_(None)) | (Job.not_before <= now))
        if not window_open:
            q = q.where(Job.trigger != "scheduled")  # manual tests and retries are not held back
        candidates = s.scalars(q.order_by(Job.created_at).limit(5)).all()
        for job_id in candidates:
            res = s.execute(update(Job).where(Job.id == job_id, Job.status == JobStatus.QUEUED)
                            .values(status=JobStatus.RUNNING).execution_options(synchronize_session=False))
            if res.rowcount != 1:
                continue  # another worker won the race
            job = s.get(Job, job_id)
            s.refresh(job)
            job.attempt_count += 1
            job.started_at = job.started_at or now
            att = JobAttempt(job_id=job.id, attempt_number=job.attempt_count, worker_id=worker_id,
                             started_at=now, heartbeat_at=now)
            s.add(att)
            s.flush()
            return job.id, att.id
    return None


def heartbeat(attempt_id: str, stage: str | None = None) -> bool:
    """Returns the job's cancel flag."""
    with session_scope() as s:
        att = s.get(JobAttempt, attempt_id)
        att.heartbeat_at = utcnow()
        if stage:
            att.stage = stage
        job = s.get(Job, att.job_id)
        return bool(job.cancel_requested)


def finish(session: Session, job: Job, status: str, *, recovery_status: str | None, cleanup_status: str | None,
           summary: dict, error_code: str | None = None, error_message: str | None = None) -> None:
    assert_job_transition(job.status, status)
    job.status = status
    job.recovery_status = recovery_status
    job.cleanup_status = cleanup_status
    job.summary_json = summary
    job.error_code, job.error_message = error_code, error_message
    if status in TERMINAL_JOB:
        job.finished_at = utcnow()
        job.active_lock = None


def requeue_for_retry(session: Session, job: Job, delay_seconds: float) -> None:
    assert_job_transition(job.status, JobStatus.QUEUED)
    job.status = JobStatus.QUEUED
    job.trigger = "retry"
    job.not_before = utcnow() + timedelta(seconds=delay_seconds)


def request_cancel(session: Session, job: Job, actor: User | None) -> None:
    if job.status == JobStatus.QUEUED:
        finish(session, job, JobStatus.CANCELLED, recovery_status=None, cleanup_status="not_required",
               summary={"reason": "cancelled before start"}, error_code="cancelled",
               error_message="cancelled before execution started")
    elif job.status == JobStatus.RUNNING:
        job.cancel_requested = True
    audit.record(session, "job.cancel_requested", actor=actor, target_type="job", target_id=job.id,
                 details={"status_at_request": job.status})


def retry_backoff(attempt_number: int) -> float:
    return min(30.0 * (2 ** (attempt_number - 1)), 900.0)


def reconcile_interrupted() -> list[str]:
    """Mark attempts whose worker stopped heart-beating as interrupted, then requeue (bounded) or close
    the job as inconclusive. Never turns an unknown outcome into a pass."""
    settings = get_settings()
    cutoff = utcnow() - timedelta(seconds=settings.stale_attempt_seconds)
    touched: list[str] = []
    with session_scope() as s:
        stale = s.scalars(select(JobAttempt).where(JobAttempt.status == AttemptStatus.RUNNING,
                                                   JobAttempt.heartbeat_at < cutoff)).all()
        for att in stale:
            assert_attempt_transition(att.status, AttemptStatus.INTERRUPTED)
            att.status = AttemptStatus.INTERRUPTED
            att.finished_at = utcnow()
            att.error_code = "worker_interrupted"
            att.error_message = (f"worker {att.worker_id} stopped reporting during stage '{att.stage}'; "
                                 "the outcome of this attempt is unknown")
            job = s.get(Job, att.job_id)
            if job.status == JobStatus.RUNNING:
                if job.cancel_requested:
                    finish(s, job, JobStatus.CANCELLED, recovery_status=None, cleanup_status="pending",
                           summary={"reason": "cancelled; worker was interrupted"}, error_code="cancelled")
                elif job.attempt_count < settings.max_attempts:
                    requeue_for_retry(s, job, retry_backoff(job.attempt_count))
                else:
                    finish(s, job, JobStatus.INCONCLUSIVE, recovery_status=AttemptStatus.INTERRUPTED,
                           cleanup_status="pending", summary={"reason": "all attempts were interrupted"},
                           error_code="worker_interrupted", error_message=att.error_message)
            audit.record(s, "attempt.interrupted", target_type="attempt", target_id=att.id,
                         details={"job_id": att.job_id, "stage": att.stage})
            touched.append(att.id)
    return touched


def register_worker(worker_id: str, hostname: str, version: str) -> None:
    with session_scope() as s:
        w = s.get(WorkerRecord, worker_id)
        if w is None:
            s.add(WorkerRecord(id=worker_id, hostname=hostname, version=version))
        else:
            w.heartbeat_at = utcnow()
            w.offline_notified = False


def worker_heartbeat(worker_id: str) -> None:
    with session_scope() as s:
        w = s.get(WorkerRecord, worker_id)
        if w:
            w.heartbeat_at = utcnow()
            w.offline_notified = False

"""Worker process: claims jobs from the durable queue and runs attempts.

On start-up and periodically it reconciles state left behind by crashed workers or host reboots.
"""

from __future__ import annotations

import logging
import os
import threading
import time

from sqlalchemy import select

from restoreproof.config import VERSION, ensure_dirs, get_settings
from restoreproof.db.models import Job, JobAttempt
from restoreproof.db.session import session_scope
from restoreproof.jobs import queue
from restoreproof.jobs.recovery import run_attempt
from restoreproof.runner.resources import reconcile_orphans

log = logging.getLogger(__name__)


class Heartbeater(threading.Thread):
    """Keeps the attempt's heartbeat fresh while long single operations (large hashes, imports) run, so the
    reconciler does not mistake a busy worker for a dead one."""

    def __init__(self, attempt_id: str, interval: float):
        super().__init__(daemon=True, name=f"heartbeat-{attempt_id[:8]}")
        self.attempt_id, self.interval = attempt_id, interval
        self.stop = threading.Event()

    def run(self) -> None:
        while not self.stop.wait(self.interval):
            try:
                queue.heartbeat(self.attempt_id)
            except Exception:  # noqa: BLE001 - DB hiccup: the next beat may succeed
                log.warning("heartbeat failed for %s", self.attempt_id)


def reconcile() -> dict:
    from restoreproof.backups import engine as backups
    backups.reconcile()
    interrupted = queue.reconcile_interrupted()
    cleaned = reconcile_orphans()
    # Propagate late cleanup results to the job of the attempt.
    with session_scope() as s:
        for item in cleaned:
            att = s.get(JobAttempt, item.get("attempt_id")) if item.get("attempt_id") else None
            if att is None:
                continue
            job = s.get(Job, att.job_id)
            if job and job.attempt_count == att.attempt_number and job.cleanup_status != att.cleanup_status:
                job.cleanup_status = att.cleanup_status
    if interrupted or cleaned:
        log.info("reconciled %d interrupted attempts, %d cleanup items", len(interrupted), len(cleaned))
    return {"interrupted": interrupted, "cleanup": cleaned}


def run_once(worker_id: str | None = None) -> str | None:
    """Claim and run at most one job. Returns the resulting status, or None if nothing was runnable."""
    settings = get_settings()
    from restoreproof.backups import engine as backups
    # Backups first: a recovery test right after a backup should see the fresh snapshot.
    rid = backups.claim(worker_id or settings.worker_id)
    if rid:
        log.info("running backup %s", rid)
        return backups.run_backup(rid)
    claimed = queue.claim_next(worker_id or settings.worker_id)
    if claimed is None:
        return None
    job_id, attempt_id = claimed
    hb = Heartbeater(attempt_id, settings.heartbeat_seconds)
    hb.start()
    try:
        log.info("running job %s attempt %s", job_id, attempt_id)
        return run_attempt(job_id, attempt_id)
    finally:
        hb.stop.set()


def run_forever(stop: threading.Event | None = None, embedded_scheduler: bool = True) -> None:
    from restoreproof.scheduler.scheduler import tick as scheduler_tick

    settings = get_settings()
    ensure_dirs(settings)
    stop = stop or threading.Event()
    queue.register_worker(settings.worker_id, os.uname().nodename, VERSION)
    reconcile()
    last_reconcile = last_tick = time.monotonic()
    last_retention = float("-inf")  # run once at start-up, then every 6 hours
    log.info("worker %s started", settings.worker_id)
    while not stop.is_set():
        try:
            queue.worker_heartbeat(settings.worker_id)
            now = time.monotonic()
            if embedded_scheduler and now - last_tick >= 30:
                last_tick = now
                scheduler_tick()
            if now - last_retention >= 6 * 3600:
                last_retention = now
                from restoreproof.evidence.retention import purge
                purge()
            if now - last_reconcile >= 60:
                last_reconcile = now
                reconcile()
            if run_once() is None:
                stop.wait(settings.worker_poll_seconds)
        except Exception:  # noqa: BLE001 - the loop must survive transient DB outages
            log.exception("worker loop error")
            stop.wait(10)


def pending_jobs() -> int:
    with session_scope() as s:
        return len(s.scalars(select(Job.id).where(Job.status == "queued")).all())

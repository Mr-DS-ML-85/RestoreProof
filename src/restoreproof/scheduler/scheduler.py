"""Database-backed scheduler.

- next_run_at is stored, so a restart never forgets or double-fires a slot
- the idempotency key `sched:<policy>:<slot>` makes duplicate ticks (two schedulers, retries) harmless
- missed slots after downtime collapse into a single run instead of a burst
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from croniter import croniter
from sqlalchemy import select

from restoreproof import audit
from restoreproof.config import get_settings
from restoreproof.db.models import Job, Policy, ProtectedApp, WorkerRecord, utcnow
from restoreproof.db.session import session_scope
from restoreproof.jobs.queue import ActiveJobExists, enqueue
from restoreproof.notifications.dispatch import notify

log = logging.getLogger(__name__)


def next_after(policy: Policy, after: datetime) -> datetime:
    tz = ZoneInfo(policy.timezone)
    it = croniter(policy.schedule, after.astimezone(tz))
    nxt: datetime = it.get_next(datetime)
    if policy.jitter_seconds:
        nxt += timedelta(seconds=random.SystemRandom().randint(0, policy.jitter_seconds))
    return nxt.astimezone(ZoneInfo("UTC"))


def next_after_cron(expr: str, tz: str, after: datetime) -> datetime:
    return croniter(expr, after.astimezone(ZoneInfo(tz))).get_next(datetime).astimezone(ZoneInfo("UTC"))


def _tick_backups(now: datetime) -> list[str]:
    from restoreproof.backups import engine
    from restoreproof.db.models import BackupPlan
    created = []
    with session_scope() as s:
        for plan in s.scalars(select(BackupPlan).where(BackupPlan.enabled.is_(True))).all():
            if plan.next_run_at is None:
                plan.next_run_at = next_after_cron(plan.schedule, plan.timezone, now)
                continue
            if plan.next_run_at > now:
                continue
            slot = plan.next_run_at
            try:
                run, new = engine.enqueue(s, plan, trigger="scheduled", idempotency_key=f"bsched:{plan.id}:{slot.isoformat()}")
                if new:
                    created.append(run.id)
            except engine.ActiveBackupExists as exc:
                audit.record(s, "backup.skipped_overlap", target_type="backup_plan", target_id=plan.id,
                             details={"slot": slot.isoformat(), "active_run": exc.run_id})
            plan.next_run_at = next_after_cron(plan.schedule, plan.timezone, max(now, slot))
    return created


def validate_schedule(expr: str, tz: str) -> None:
    if not croniter.is_valid(expr):
        raise ValueError(f"invalid cron expression {expr!r}")
    ZoneInfo(tz)


def tick(now: datetime | None = None) -> list[str]:
    now = now or utcnow()
    created: list[str] = []
    with session_scope() as s:
        rows = s.execute(select(Policy, ProtectedApp).join(ProtectedApp, ProtectedApp.id == Policy.app_id)
                         .where(Policy.enabled.is_(True), ProtectedApp.archived.is_(False))).all()
        for policy, app in rows:
            if policy.next_run_at is None:
                policy.next_run_at = next_after(policy, now)
                continue
            if policy.next_run_at > now:
                continue
            slot = policy.next_run_at
            try:
                job, new = enqueue(s, app, trigger="scheduled", idempotency_key=f"sched:{policy.id}:{slot.isoformat()}")
                if new:
                    created.append(job.id)
            except ActiveJobExists as exc:
                audit.record(s, "schedule.skipped_overlap", target_type="app", target_id=app.id,
                             details={"slot": slot.isoformat(), "active_job": exc.job_id})
            policy.last_scheduled_at = slot
            # Collapse missed slots: the next run is computed from *now*, not from the missed slot.
            policy.next_run_at = next_after(policy, max(now, slot))
    created += _tick_backups(now)
    _check_overdue(now)
    _check_workers(now)
    return created


def _check_overdue(now: datetime) -> None:
    with session_scope() as s:
        rows = s.execute(select(Policy, ProtectedApp).join(ProtectedApp, ProtectedApp.id == Policy.app_id)
                         .where(Policy.enabled.is_(True), ProtectedApp.archived.is_(False))).all()
        for policy, app in rows:
            last_pass = s.scalars(select(Job.finished_at).where(Job.app_id == app.id, Job.status == "passed")
                                  .order_by(Job.finished_at.desc()).limit(1)).first()
            limit = timedelta(hours=policy.max_age_last_success_hours)
            reference = last_pass or app.created_at
            if now - reference <= limit:
                policy.overdue_notified_at = None
                continue
            if policy.overdue_notified_at and now - policy.overdue_notified_at < limit:
                continue
            policy.overdue_notified_at = now
            notify("test_overdue", {"application": app.name, "app_id": app.id,
                                    "message": f"no passing recovery test in {policy.max_age_last_success_hours}h"
                                               + ("" if last_pass else " (never passed)"),
                                    "report_url": f"{get_settings().base_url}/#/apps/{app.id}"})


def _check_workers(now: datetime) -> None:
    """Alert only when no worker is online (tests cannot run). A worker replaced by a restart or upgrade
    leaves a stale record behind; that is not an outage, so it is retired silently."""
    settings = get_settings()
    cutoff = now - timedelta(seconds=max(settings.stale_attempt_seconds, settings.heartbeat_seconds * 6))
    with session_scope() as s:
        workers = s.scalars(select(WorkerRecord)).all()
        online = [w for w in workers if w.heartbeat_at >= cutoff]
        stale = [w for w in workers if w.heartbeat_at < cutoff]
        for w in stale:
            if now - w.heartbeat_at > timedelta(days=7):
                s.delete(w)
        if online or not workers:
            for w in stale:
                w.offline_notified = True
            return
        if any(not w.offline_notified for w in stale):
            last = max(w.heartbeat_at for w in stale)
            for w in stale:
                w.offline_notified = True
            notify("worker_offline", {"message": f"no RestoreProof worker is running (last seen {last.isoformat()}); "
                                                 "scheduled recovery tests will not run",
                                      "next_step": "Start the worker: `docker compose up -d worker` or "
                                                   "`restoreproof worker`, then check `restoreproof doctor`."})

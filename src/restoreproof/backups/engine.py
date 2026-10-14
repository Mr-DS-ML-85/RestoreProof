"""Backup execution: pick a destination, make the data consistent, back up, apply retention, verify.

Destination choice is "first fit" over the plan's ordered list:
  local destination  -> only if free space minus the expected new data still leaves the reserve free
                        (max(min_free_percent of the disk, RESTOREPROOF_MIN_FREE_BYTES)); otherwise skip it
  any destination    -> the repository must open (managed destinations are initialised on first use)
Every candidate's verdict is recorded on the run, so "why did it go to the NAS?" always has an answer.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import shutil
import socket
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.adapters.base import AdapterError
from restoreproof.backups import hooks as hk
from restoreproof.backups.writer import ResticWriter
from restoreproof.config import get_settings
from restoreproof.db.models import BackupPlan, BackupRun, BackupSource, JobAttempt, Job, ProtectedApp, utcnow
from restoreproof.db.session import session_scope
from restoreproof.evidence.sanitization import Sanitizer, truncate
from restoreproof.notifications.dispatch import notify
from restoreproof.security.crypto import load_secret

log = logging.getLogger(__name__)
MIB = 1024 * 1024
TERMINAL = {"succeeded", "partial", "failed", "blocked"}


class ActiveBackupExists(Exception):
    def __init__(self, run_id: str):
        super().__init__(run_id)
        self.run_id = run_id


def human(n: int | float | None) -> str:
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


# -- queue ---------------------------------------------------------------------------------------------------
def enqueue(session: Session, plan: BackupPlan, *, trigger: str, idempotency_key: str | None = None,
            actor=None) -> tuple[BackupRun, bool]:
    if idempotency_key:
        existing = session.scalar(select(BackupRun).where(BackupRun.idempotency_key == idempotency_key))
        if existing:
            return existing, False
    run = BackupRun(plan_id=plan.id, trigger=trigger, idempotency_key=idempotency_key, active_lock=plan.id)
    try:
        with session.begin_nested():
            session.add(run)
            session.flush()
    except IntegrityError:
        active = session.scalar(select(BackupRun).where(BackupRun.active_lock == plan.id))
        raise ActiveBackupExists(active.id if active else "unknown") from None
    audit.record(session, "backup.queued", actor=actor, target_type="backup_plan", target_id=plan.id,
                 details={"trigger": trigger})
    return run, True


def running_count(s: Session) -> int:
    tests = s.scalar(select(func.count()).select_from(JobAttempt).where(JobAttempt.status == "running")) or 0
    backups = s.scalar(select(func.count()).select_from(BackupRun).where(BackupRun.status == "running")) or 0
    return tests + backups


def claim(worker_id: str) -> str | None:
    settings = get_settings()
    with session_scope() as s:
        if running_count(s) >= settings.max_concurrent_jobs:
            return None
        for rid in s.scalars(select(BackupRun.id).where(BackupRun.status == "queued")
                             .order_by(BackupRun.created_at).limit(5)).all():
            from sqlalchemy import update
            res = s.execute(update(BackupRun).where(BackupRun.id == rid, BackupRun.status == "queued")
                            .values(status="running", worker_id=worker_id, started_at=utcnow(), heartbeat_at=utcnow())
                            .execution_options(synchronize_session=False))
            if res.rowcount == 1:
                return rid
    return None


def finish(s: Session, run: BackupRun, status: str, **fields: Any) -> None:
    run.status = status
    run.finished_at = utcnow()
    run.active_lock = None
    if run.started_at:
        run.duration_ms = int((run.finished_at - run.started_at).total_seconds() * 1000)
    for k, v in fields.items():
        setattr(run, k, v)


def reconcile() -> list[str]:
    """Backups whose worker died: mark failed (restic snapshots are atomic, so a re-run is safe) and make sure
    no container stays paused."""
    cutoff = utcnow() - timedelta(seconds=get_settings().stale_attempt_seconds)
    done = []
    with session_scope() as s:
        for run in s.scalars(select(BackupRun).where(BackupRun.status == "running",
                                                     BackupRun.heartbeat_at < cutoff)).all():
            for entry in run.decision or []:
                if entry.get("paused"):
                    hk.unpause(entry["paused"])
            finish(s, run, "failed", error_code="worker_interrupted",
                   error_message="the worker stopped during this backup; no snapshot was recorded by it. "
                                 "Run it again; restic does not keep half-finished snapshots.")
            done.append(run.id)
    return done


# -- sizing / destination choice ---------------------------------------------------------------------------
def measure(paths: list[str], excludes: list[str], skip: list[Path], limit_s: float = 300) -> tuple[int, int]:
    """(bytes, files) under paths, honouring simple exclude globs; bounded in time."""
    total = files = 0
    deadline = time.monotonic() + limit_s
    skip_r = [p.resolve() for p in skip]
    for root in paths:
        for dirpath, dirs, names in os.walk(root, followlinks=False):
            dp = Path(dirpath).resolve()
            if any(dp == sk or sk in dp.parents for sk in skip_r):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, e) for e in excludes)]
            for n in names:
                if any(fnmatch.fnmatch(n, e) for e in excludes):
                    continue
                try:
                    total += os.lstat(os.path.join(dirpath, n)).st_size
                    files += 1
                except OSError:
                    pass
            if time.monotonic() > deadline:
                return total, files
    return total, files


def existing_ancestor(path: Path) -> Path:
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    return p


def expected_new_bytes(s: Session, plan_id: str, dest_id: str, source_bytes: int, first: bool) -> int:
    if first:
        return source_bytes
    prev = s.scalars(select(BackupRun.bytes_added).where(
        BackupRun.plan_id == plan_id, BackupRun.destination_id == dest_id,
        BackupRun.status.in_(["succeeded", "partial"]), BackupRun.bytes_added.is_not(None))
        .order_by(BackupRun.finished_at.desc()).limit(3)).all()
    recent = max(prev) if prev else source_bytes
    return int(max(recent * 2, source_bytes * 0.05, 64 * MIB))


# -- run ---------------------------------------------------------------------------------------------------
class _Heartbeat(threading.Thread):
    def __init__(self, run_id: str):
        super().__init__(daemon=True)
        self.run_id, self.stop = run_id, threading.Event()

    def run(self) -> None:
        while not self.stop.wait(5):
            try:
                with session_scope() as s:
                    s.get(BackupRun, self.run_id).heartbeat_at = utcnow()
            except Exception:  # noqa: BLE001
                pass


def _writer(s: Session, src: BackupSource, sanitizer: Sanitizer) -> ResticWriter:
    return ResticWriter(src.config_json, load_secret(s, src.secret_ref), sanitizer, priority="low")


def run_backup(run_id: str) -> str:
    settings = get_settings()
    sanitizer = Sanitizer()
    lines: list[str] = []
    decision: list[dict[str, Any]] = []
    paused: list[str] = []
    hb = _Heartbeat(run_id)
    hb.start()
    writer: ResticWriter | None = None
    try:
        with session_scope() as s:
            run = s.get(BackupRun, run_id)
            plan = s.get(BackupPlan, run.plan_id)
            plan_snapshot = {"id": plan.id, "name": plan.name, "paths": list(plan.paths), "excludes": list(plan.excludes),
                             "destination_ids": list(plan.destination_ids), "hooks": list(plan.hooks),
                             "retention": dict(plan.retention or {}), "min_free_percent": plan.min_free_percent,
                             "verify_app_ids": list(plan.verify_app_ids)}
        p = plan_snapshot
        tag = f"rp-plan-{p['id'][:8]}"

        missing = [x for x in p["paths"] if not Path(x).exists()]
        if missing:
            return _end(run_id, "failed", decision, lines, error_code="source_missing",
                        error_message=f"backup path(s) do not exist: {', '.join(missing)}. Is the volume mounted?")

        # 1) consistency hooks
        try:
            for h in hk.parse(p["hooks"]):
                if h.type == "pause_container":
                    hk.pause(h.container)
                    paused.append(h.container)
                    decision.append({"paused": h.container})
                    lines.append(f"paused container {h.container}")
                elif h.type == "sqlite_backup":
                    lines.append(hk.run_sqlite_backup(h))
                elif h.type == "postgres_dump":
                    lines.append(hk.run_postgres_dump(h))
        except (hk.HookError, OSError) as exc:
            return _end(run_id, "failed", decision, lines, error_code="hook_failed",
                        error_message=f"{exc}. The backup was not started, so the previous good copy is untouched.")

        # 2) size the job
        source_bytes, source_files = measure(p["paths"], p["excludes"], [settings.temp_root, settings.data_dir])
        lines.append(f"source: {source_files} files, {human(source_bytes)}")

        # 3) choose a destination (first fit)
        chosen: BackupSource | None = None
        with session_scope() as s:
            for did in p["destination_ids"]:
                src = s.get(BackupSource, did)
                if src is None:
                    decision.append({"destination": did, "verdict": "skipped", "reason": "destination was deleted"})
                    continue
                loc_raw = (src.config_json or {}).get("location")
                label = src.name
                try:
                    if writer:
                        writer.close()
                    writer = _writer(s, src, sanitizer)
                except AdapterError as exc:
                    decision.append({"destination": label, "verdict": "skipped", "reason": str(exc)})
                    continue
                first = True
                ok, code = writer.exists()
                if ok:
                    first = not writer.has_tag(tag)
                if loc_raw and loc_raw.get("type") == "local":
                    target = Path(loc_raw["path"])
                    du = shutil.disk_usage(existing_ancestor(target))
                    need = expected_new_bytes(s, p["id"], src.id, source_bytes, first)
                    reserve = max(int(du.total * p["min_free_percent"] / 100), settings.min_free_bytes)
                    if du.free - need < reserve:
                        decision.append({"destination": label, "verdict": "skipped", "reason":
                                         f"not enough space: needs ~{human(need)}, {human(du.free)} free, "
                                         f"must keep {human(reserve)} free"})
                        continue
                    space_note = f"{human(du.free)} free, needs ~{human(need)}, keeps {human(reserve)} free"
                else:
                    space_note = "remote"
                if not ok:
                    if code in ("repository_unavailable",) and (src.config_json or {}).get("managed"):
                        try:
                            writer.init()
                            lines.append(f"initialised a new repository at {label}")
                            first = True
                        except AdapterError as exc:
                            decision.append({"destination": label, "verdict": "skipped",
                                             "reason": f"could not create repository: {exc}"})
                            continue
                    else:
                        decision.append({"destination": label, "verdict": "skipped",
                                         "reason": f"repository not reachable ({code})"})
                        continue
                decision.append({"destination": label, "verdict": "chosen", "reason": space_note})
                chosen = src
                chosen_id = src.id
                break
        if chosen is None:
            return _end(run_id, "blocked", decision, lines, error_code="no_destination",
                        error_message="no destination could take this backup: " +
                                      "; ".join(f"{d['destination']}: {d['reason']}" for d in decision if 'destination' in d))

        # 4) back up
        try:
            res = writer.backup(p["paths"], excludes=p["excludes"] + [str(settings.temp_root)], tags=[tag, "restoreproof"],
                                host=socket.gethostname(), timeout=6 * 3600)
        except AdapterError as exc:
            return _end(run_id, "failed", decision, lines, destination_id=chosen_id, error_code=exc.code,
                        error_message=str(exc))
        lines.append(f"snapshot {res.get('snapshot_id', '')[:12]}: {res.get('files_new', 0)} new, "
                     f"{res.get('files_changed', 0)} changed, {human(res.get('data_added'))} added")
        status = "partial" if res.get("partial") else "succeeded"
        fields: dict[str, Any] = dict(destination_id=chosen_id, snapshot_id=res.get("snapshot_id"),
                                      source_bytes=source_bytes, bytes_added=res.get("data_added"),
                                      files_new=res.get("files_new"), files_changed=res.get("files_changed"))
        if res.get("partial"):
            fields.update(error_code="unreadable_files", error_message=(
                "the snapshot was saved but some files could not be read and are missing from it: "
                + "; ".join(res["errors"][:5])))

        # 5) retention
        ret = p["retention"]
        if ret.get("enabled"):
            with session_scope() as s:
                busy = s.scalar(select(func.count()).select_from(JobAttempt).join(Job, Job.id == JobAttempt.job_id)
                                .join(ProtectedApp, ProtectedApp.id == Job.app_id)
                                .where(JobAttempt.status == "running", ProtectedApp.source_id == chosen_id)) or 0
            fields["retention_result"] = writer.apply_retention(tag, ret, prune=not busy, timeout=6 * 3600)
            lines.append(fields["retention_result"])

        # 6) verify: queue recovery tests that read this destination
        verify_ids, notes = [], []
        with session_scope() as s:
            from restoreproof.jobs.queue import ActiveJobExists, enqueue as enqueue_test
            for aid in p["verify_app_ids"]:
                app = s.get(ProtectedApp, aid)
                if app is None or app.archived:
                    continue
                if app.source_id != chosen_id:
                    notes.append(f"{app.name}: not verified (its test reads another destination)")
                    continue
                try:
                    job, _ = enqueue_test(s, app, trigger="after_backup", idempotency_key=f"afterbackup:{run_id}:{aid}")
                    verify_ids.append(job.id)
                except ActiveJobExists:
                    notes.append(f"{app.name}: a test is already running")
        lines += notes
        fields["verify_job_ids"] = verify_ids
        return _end(run_id, status, decision, lines, **fields)
    except Exception as exc:  # noqa: BLE001
        log.exception("backup %s crashed", run_id)
        return _end(run_id, "failed", decision, lines, error_code="internal_error",
                    error_message=truncate(sanitizer.text(f"{type(exc).__name__}: {exc}"), 500))
    finally:
        for c in paused:
            lines.append(hk.unpause(c))
        if writer:
            writer.close()
        hb.stop.set()


def _end(run_id: str, status: str, decision: list, lines: list[str], **fields: Any) -> str:
    settings = get_settings()
    d = settings.reports_dir / "backups"
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{run_id}.log").write_text(Sanitizer().text("\n".join(lines)))
        fields["log_path"] = str(d / f"{run_id}.log")
    except OSError:
        pass
    with session_scope() as s:
        run = s.get(BackupRun, run_id)
        plan = s.get(BackupPlan, run.plan_id)
        finish(s, run, status, decision=decision, **fields)
        audit.record(s, f"backup.{status}", target_type="backup_plan", target_id=run.plan_id,
                     details={"run_id": run_id, "destination": next((x["destination"] for x in decision
                                                                      if x.get("verdict") == "chosen"), None)})
        payload = {"application": f"backup: {plan.name}", "status": status, "run_id": run_id,
                   "message": fields.get("error_message"), "report_url": f"{settings.base_url}/#/backups/{plan.id}"}
    if status in ("failed", "blocked", "partial"):
        notify("backup_failed", payload)
    return status

"""One recovery-test attempt, end to end.

Layers (PRD §4), each with its own status:
  recovery_point -> data -> database -> application -> objectives (advisory)
then evidence is persisted, temporary resources are cleaned up, and the sealed report is written.

Every check result is committed as soon as it is known, so a crash mid-run still leaves evidence behind.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select

from restoreproof.adapters.base import AdapterError, BackupAdapter, RecoveryPointInfo
from restoreproof.adapters.restic import build_adapter
from restoreproof.checks import files as file_checks
from restoreproof.checks import http as http_checks
from restoreproof.checks import inventory as inventory_checks
from restoreproof.checks import mysql as mysql_checks
from restoreproof.checks import postgres as pg_checks
from restoreproof.checks import sqlite as sqlite_checks
from restoreproof.checks.base import CheckRecord, timed
from restoreproof.config import VERSION, get_settings
from restoreproof.db.models import (
    BackupSource,
    Baseline,
    CheckResult,
    EvidenceArtifact,
    Job,
    JobAttempt,
    ManagedResource,
    ProtectedApp,
    RecoveryPoint,
    TestDefinitionVersion,
    utcnow,
)
from restoreproof.db.session import session_scope
from restoreproof.definitions import (
    APP_CHECKS,
    DB_CHECKS,
    FILE_CHECKS,
    MYSQL_CHECKS,
    SQLITE_CHECKS,
    DefinitionError,
    RecoveryTest,
    check_label,
    parse_definition,
)
from restoreproof.evidence import manifest as mf
from restoreproof.evidence.reports import render_html
from restoreproof.evidence.sanitization import Sanitizer, truncate
from restoreproof.jobs import queue
from restoreproof.jobs.selection import select_recovery_point
from restoreproof.jobs.state_machine import (
    AttemptStatus,
    CheckOutcome,
    CheckStatus as S,
    CleanupStatus,
    JobStatus,
    aggregate,
    assert_attempt_transition,
    layer_statuses,
)
from restoreproof.notifications.dispatch import notify
from restoreproof.remediation import (
    ERROR_HINTS,
    MISSING_HINT,
    hint_for,
    infer_base_path,
    suggest_base_path,
    suggest_similar_path,
)
from restoreproof.runner.docker import DockerEnvironment, DockerError, docker_available
from restoreproof.runner.resources import cleanup_attempt, register_resource
from restoreproof.security.crypto import SecretUnavailable, load_secret
from restoreproof.security.paths import create_run_dir, dir_usage, resolve_within, UnsafePath
from restoreproof.security.process import AbortRequested

log = logging.getLogger(__name__)


class StopRun(Exception):
    """Ends the run early with a definite attempt status."""

    def __init__(self, status: AttemptStatus, code: str, message: str, transient: bool = False):
        super().__init__(message)
        self.status, self.code, self.transient = status, code, transient


class AttemptRunner:
    def __init__(self, job_id: str, attempt_id: str):
        self.settings = get_settings()
        self.job_id, self.attempt_id = job_id, attempt_id
        self.sanitizer = Sanitizer()
        self.records: list[CheckRecord] = []
        self.timings: dict[str, int] = {}
        self.stages: list[dict[str, Any]] = []
        self.logs: list[str] = []
        self.started = utcnow()
        self.t0 = time.monotonic()
        self.adapter: BackupAdapter | None = None
        self.env: DockerEnvironment | None = None
        self.run_dir: Path | None = None
        self.point: RecoveryPointInfo | None = None
        self.selection_reason = ""
        self.tool_version = "unknown"
        self.restored: tuple[int, int] | None = None
        self._last_beat = 0.0
        self._last_size = 0.0
        self._cancel = False
        self._last_error_code: str | None = None
        with session_scope() as s:
            self.job = s.get(Job, job_id)
            self.app = s.get(ProtectedApp, self.job.app_id)
            self.source = s.get(BackupSource, self.app.source_id)
            ver = s.scalar(select(TestDefinitionVersion).where(
                TestDefinitionVersion.app_id == self.app.id,
                TestDefinitionVersion.version == self.job.definition_version))
            self.definition_text = ver.yaml if ver else self.app.test_definition
            self.attempt_number = s.get(JobAttempt, attempt_id).attempt_number
        self.defn: RecoveryTest | None = None
        self.deadline = self.t0 + 3600

    # -- bookkeeping ---------------------------------------------------------------------------------------
    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def beat(self, stage: str | None = None, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self._last_beat >= min(self.settings.heartbeat_seconds, 5):
            self._last_beat = now
            self._cancel = queue.heartbeat(self.attempt_id, stage) or self._cancel
            queue.worker_heartbeat(self.settings.worker_id)

    def guard(self) -> None:
        self.beat()
        if self._cancel:
            raise StopRun(AttemptStatus.CANCELLED, "cancelled", "cancellation was requested")
        if self.remaining() <= 0:
            raise StopRun(AttemptStatus.TIMED_OUT, "timeout",
                          f"maxDurationSeconds={self.defn.spec.restore.maxDurationSeconds if self.defn else '?'} reached")

    def poll(self) -> None:
        """Called while a subprocess runs: heartbeat, cancellation, and restore budget enforcement."""
        self.beat()
        if self._cancel:
            raise AbortRequested("cancelled", "cancellation was requested")
        now = time.monotonic()
        if self.run_dir is not None and now - self._last_size >= 3:
            self._last_size = now
            spec = self.defn.spec.restore if self.defn else None
            if spec and spec.maxBytes:
                _, used = dir_usage(self.run_dir / "restore")
                if used > spec.maxBytes:
                    raise AbortRequested("budget_exceeded", f"restore exceeded maxBytes={spec.maxBytes}")
            free = shutil.disk_usage(self.settings.temp_root).free
            if free < self.settings.min_free_bytes // 2:
                raise AbortRequested("disk_low", "free disk space fell below the safety threshold")

    def add(self, layer: str, name: str, check_type: str, status: str, message: str, *, required: bool = True,
            details: dict | None = None, duration_ms: int = 0) -> CheckRecord:
        details = dict(details or {})
        if details.get("missing_path") and self.run_dir is not None and "suggestions" not in details:
            similar = suggest_similar_path(self.run_dir / "restore", details["missing_path"])
            if similar:
                details["suggestions"] = similar
                message += f". Found similarly named: {similar[0]}"
            details.setdefault("hint", MISSING_HINT)
        if str(status) in (S.FAILED, S.ERROR) and "hint" not in details:
            hint = hint_for(check_type, name)
            if hint:
                details["hint"] = hint
        rec = CheckRecord(layer, name, check_type, required, str(status), self.sanitizer.text(message)[:2000],
                          duration_ms, self.sanitizer.obj(details))
        self.records.append(rec)
        with session_scope() as s:
            s.add(CheckResult(attempt_id=self.attempt_id, seq=len(self.records), layer=layer, name=name[:200],
                              check_type=check_type, required=required, status=rec.status,
                              duration_ms=duration_ms, message=rec.message,
                              details_json=json.loads(json.dumps(rec.details, default=str))))
        return rec

    @contextmanager
    def stage(self, name: str):
        self.guard()
        self.beat(name, force=True)
        t = time.monotonic()
        entry = {"stage": name, "started_at": utcnow().isoformat(), "status": "running"}
        self.stages.append(entry)
        try:
            yield
            entry["status"] = "completed"
        except StopRun as exc:
            entry["status"] = exc.status.value
            raise
        except Exception:
            entry["status"] = "error"
            raise
        finally:
            entry["duration_ms"] = self.timings[name] = int((time.monotonic() - t) * 1000)

    def _update_attempt(self, **fields: Any) -> None:
        with session_scope() as s:
            att = s.get(JobAttempt, self.attempt_id)
            for k, v in fields.items():
                setattr(att, k, v)

    def _adapter_stop(self, exc: AdapterError) -> StopRun:
        if exc.code == "cancelled":
            return StopRun(AttemptStatus.CANCELLED, "cancelled", "cancellation was requested")
        if exc.code in ("budget_exceeded", "disk_low"):
            return StopRun(AttemptStatus.BLOCKED, exc.code, str(exc))
        if exc.code == "timeout":
            return StopRun(AttemptStatus.TIMED_OUT, "timeout", str(exc))
        return StopRun(AttemptStatus.INCONCLUSIVE, exc.code, str(exc), transient=exc.transient)

    def _need_docker(self) -> DockerEnvironment | None:
        if self.env is not None:
            return self.env
        ok, info = docker_available()
        if not ok:
            return None
        self.env = DockerEnvironment(self.attempt_id, self.run_dir, lambda t, e: register_resource(
            self.attempt_id, t, e), self.sanitizer)
        self.env.create_network()
        return self.env

    def _docker_for(self, layer: str) -> DockerEnvironment | None:
        """The attempt's isolated container environment, or None (with a recorded reason) if unusable."""
        if self.base is None or not self.restore_ok:
            return None  # dependent checks are recorded as skipped
        try:
            env = self._need_docker()
        except DockerError as exc:
            self.add(layer, "isolated_network", "docker", S.ERROR, str(exc))
            return None
        if env is None:
            self.add(layer, "container_runtime", "docker", S.ERROR,
                     f"Docker is not available to this worker; {layer} checks could not run")
            return None
        env.deadline = self.deadline
        return env

    # -- layers --------------------------------------------------------------------------------------------
    def _load_definition(self) -> None:
        try:
            self.defn = parse_definition(self.definition_text)
        except DefinitionError as exc:
            raise StopRun(AttemptStatus.BLOCKED, "invalid_definition", f"test definition is invalid: {exc}") from exc
        self.deadline = self.t0 + self.defn.spec.restore.maxDurationSeconds

    def layer_recovery_point(self) -> None:
        spec = self.defn.spec
        with self.stage("source_validation"):
            with session_scope() as s:
                try:
                    secret = load_secret(s, self.source.secret_ref)
                except SecretUnavailable as exc:
                    self.add("recovery_point", "credentials_available", "credentials", S.ERROR, str(exc))
                    raise StopRun(AttemptStatus.BLOCKED, "secret_unavailable", str(exc)) from exc
            for v in _flatten_strings(secret):
                self.sanitizer.add(v)
            try:
                self.adapter = build_adapter(self.source.adapter, self.source.config_json, secret, self.sanitizer,
                                             priority=spec.restore.priority,
                                             limit_download_kib=spec.restore.limitDownloadKiB)
            except AdapterError as exc:
                self.add("recovery_point", "source_configuration", "source_config", S.ERROR, str(exc))
                raise StopRun(AttemptStatus.BLOCKED, exc.code, str(exc)) from exc
            self.tool_version = self.adapter.tool_version()
            res = self.adapter.validate_credentials()
            self.logs.append(res.log)
            if not res.ok:
                code = res.details.get("code", "adapter_error")
                transient = code in ("repository_unavailable", "repository_locked", "timeout")
                # Wrong credentials are a real recoverability failure; an unreachable repository is unknown.
                self.add("recovery_point", "repository_access", "repository_access",
                         S.ERROR if transient else S.FAILED, res.message, details={"code": code},
                         duration_ms=res.duration_ms)
                notify("source_failure", self._notify_payload(message=f"{code}: {res.message}"))
                raise StopRun(AttemptStatus.INCONCLUSIVE if transient else AttemptStatus.FAILED, code, res.message,
                              transient=transient)
            self.add("recovery_point", "repository_access", "repository_access", S.PASSED, res.message,
                     duration_ms=res.duration_ms)

        with self.stage("discovery"):
            try:
                points = self.adapter.list_recovery_points()
            except AdapterError as exc:
                self.logs.append(exc.details.get("log", ""))
                self.add("recovery_point", "recovery_point_discovery", "discovery", S.ERROR, str(exc))
                raise self._adapter_stop(exc) from exc
            _store_points(self.source.id, points)
            sel = select_recovery_point(points, spec.source.recoveryPoint, utcnow(),
                                        pinned_override=self.job.pinned_recovery_point)
            self.selection_reason = sel.reason
            if sel.point is None:
                self.add("recovery_point", "recovery_point_selected", "selection", S.FAILED, sel.reason,
                         details={"available": len(points)})
                if spec.source.recoveryPoint.onMissing == "block":
                    raise StopRun(AttemptStatus.BLOCKED, "recovery_point_missing", sel.reason)
                raise StopRun(AttemptStatus.FAILED, "recovery_point_missing", sel.reason)
            self.point = sel.point
            self._update_attempt(recovery_point_native_id=sel.point.native_id,
                                 recovery_point_time=sel.point.created_at)
            age_h = (utcnow() - sel.point.created_at).total_seconds() / 3600
            self.add("recovery_point", "recovery_point_selected", "selection", S.PASSED,
                     f"{sel.point.native_id[:12]} from {sel.point.created_at.isoformat()} ({age_h:.1f}h old); "
                     f"{sel.reason}", details={"native_id": sel.point.native_id, "age_hours": round(age_h, 2),
                                                "eligible": sel.eligible_count})
            rpo = spec.objectives.rpoHours
            if rpo:
                ok = age_h <= rpo
                self.add("objectives", "rpo_freshness", "rpo", S.PASSED if ok else S.FAILED,
                         f"recovery point age {age_h:.1f}h {'within' if ok else 'exceeds'} RPO target {rpo}h",
                         required=False, details={"age_hours": round(age_h, 2), "rpo_hours": rpo})

    def layer_data(self) -> None:
        spec = self.defn.spec
        with self.stage("preflight"):
            estimate = self.adapter.estimate_restore_size(self.point.native_id, timeout=min(self.remaining(), 600))
            free = shutil.disk_usage(self.settings.temp_root).free
            details = {"estimated_bytes": estimate, "free_bytes": free, "max_bytes": spec.restore.maxBytes,
                       "min_free_bytes": self.settings.min_free_bytes}
            if estimate is not None and spec.restore.maxBytes and estimate > spec.restore.maxBytes:
                self.add("data", "storage_budget", "preflight", S.ERROR,
                         f"estimated restore size {estimate} exceeds maxBytes {spec.restore.maxBytes}", details=details)
                raise StopRun(AttemptStatus.BLOCKED, "budget_exceeded", "estimated restore exceeds the storage budget")
            if free - (estimate or 0) < self.settings.min_free_bytes:
                self.add("data", "storage_budget", "preflight", S.ERROR,
                         "insufficient free disk space for this restore", details=details)
                raise StopRun(AttemptStatus.BLOCKED, "insufficient_disk", "insufficient free disk space")
            self.add("data", "storage_budget", "preflight", S.PASSED,
                     f"estimated {estimate if estimate is not None else 'unknown'} bytes, {free} bytes free",
                     required=False, details=details)

        if spec.repository.check:
            with self.stage("repository_check"):
                try:
                    res = self.adapter.check_repository(read_data_subset=spec.repository.readDataSubset,
                                                        timeout=self.remaining(), poll=self.poll)
                except AdapterError as exc:
                    self.logs.append(exc.details.get("log", ""))
                    self.add("data", "repository_integrity", "repository_check", S.ERROR, str(exc))
                    raise self._adapter_stop(exc) from exc
                self.logs.append(res.log)
                self.add("data", "repository_integrity", "repository_check", S.PASSED if res.ok else S.FAILED,
                         res.message, details=res.details, duration_ms=res.duration_ms)

        with self.stage("restore"):
            # Register first, create second: a crash in between still leaves a cleanup record.
            target = self.settings.temp_root / f"run-{self.attempt_id}"
            register_resource(self.attempt_id, "directory", str(target))
            self.run_dir = create_run_dir(self.settings.temp_root, self.attempt_id, self.job_id)
            dest = self.run_dir / "restore"
            self._update_attempt(restore_dir=str(self.run_dir))
            try:
                res = self.adapter.restore_to_destination(self.point.native_id, dest, include=spec.source.include,
                                                          timeout=self.remaining(), poll=self.poll)
            except AdapterError as exc:
                self.logs.append(exc.details.get("log", ""))
                self.add("data", "restore_completed", "restore", S.ERROR, str(exc))
                raise self._adapter_stop(exc) from exc
            self.logs.append(res.log)
            self.restored = dir_usage(dest)
            self._update_attempt(restored_files=self.restored[0], restored_bytes=self.restored[1])
            details = {**res.details, "files": self.restored[0], "bytes": self.restored[1]}
            self.add("data", "restore_completed", "restore", S.PASSED if res.ok else S.FAILED,
                     f"{res.message}: {self.restored[0]} files, {self.restored[1]} bytes", details=details,
                     duration_ms=res.duration_ms)
            self.restore_ok = res.ok

        with self.stage("file_validation"):
            self.base = self._restore_base()
            for i, c in enumerate(spec.checks):
                if c.type not in FILE_CHECKS:
                    continue
                self.guard()
                if self.base is None or not self.restore_ok:
                    why = "restore did not complete successfully" if not self.restore_ok else \
                        "restore basePath is missing"
                    self.add("data", check_label(c, i), c.type, S.SKIPPED, why, required=c.required)
                    continue
                status, msg, details, ms = timed(lambda c=c: file_checks.run_file_check(c, self.base))
                self.add("data", check_label(c, i), c.type, status, msg, required=c.required, details=details,
                         duration_ms=ms)
            self._inventory_checks()

        sqlite = [(i, c) for i, c in enumerate(spec.checks) if c.type in SQLITE_CHECKS]
        if sqlite:
            with self.stage("sqlite_validation"):
                scratch = self.run_dir / "scratch"
                scratch.mkdir(exist_ok=True)
                for i, c in sqlite:
                    self.guard()
                    if self.base is None or not self.restore_ok:
                        self.add("database", check_label(c, i), c.type, S.SKIPPED, "restore did not complete",
                                 required=c.required)
                        continue
                    status, msg, details, ms = timed(lambda c=c: sqlite_checks.run_sqlite_check(
                        c, self.base, scratch, timeout_s=max(5.0, min(300.0, self.remaining()))))
                    self.add("database", check_label(c, i), c.type, status, msg, required=c.required,
                             details=details, duration_ms=ms)

    def _inventory_checks(self) -> None:
        for i, c in enumerate(self.defn.spec.checks):
            if c.type != "inventory":
                continue
            self.guard()
            name = check_label(c, i)
            if self.base is None or not self.restore_ok:
                self.add("data", name, c.type, S.SKIPPED, "restore did not complete", required=c.required)
                continue
            with session_scope() as s:
                bl = s.scalar(select(Baseline).where(Baseline.app_id == self.app.id, Baseline.check_name == name,
                                                     Baseline.active.is_(True)))
                baseline_meta = (bl.id, bl.content, bl.sha256, bl.approved_at) if bl else None
            baseline = None
            if baseline_meta:
                try:
                    baseline = inventory_checks.load_baseline(baseline_meta[1], baseline_meta[2])
                except (OSError, ValueError, KeyError):
                    self.add("data", name, c.type, S.ERROR, "the approved baseline file cannot be read",
                             required=c.required)
                    continue
            t = time.monotonic()
            try:
                status, msg, details, obs = inventory_checks.run_inventory(c, self.base, baseline)
            except OSError as exc:
                status, msg, details, obs = S.ERROR, f"inventory could not be built: {exc}", {}, None
            ms = int((time.monotonic() - t) * 1000)
            if obs is not None:
                fname = f"inventory-{re.sub(r'[^A-Za-z0-9._-]', '_', name)[:80]}.json"
                self._write_artifact("inventory", fname, json.dumps(obs, sort_keys=True), name=name)
            if baseline_meta:
                details["baseline_id"], details["baseline_approved_at"] = baseline_meta[0], baseline_meta[3]
            # Without a baseline there is nothing independent to compare against: advisory for this run only.
            self.add("data", name, c.type, status, msg, required=c.required and baseline is not None,
                     details=details, duration_ms=ms)

    def _restore_base(self) -> Path | None:
        bp = self.defn.spec.restore.basePath
        root = self.run_dir / "restore"
        try:
            base = root.resolve() if bp == "." else resolve_within(root, bp)
        except UnsafePath as exc:
            self.add("data", "restore_base_present", "restore", S.FAILED, str(exc))
            return None
        if not base.is_dir():
            candidates = suggest_base_path(root, bp)
            msg = f"basePath {bp!r} does not exist in the restored data"
            if candidates:
                msg += f". Try basePath: {candidates[0]!r}"
            self.add("data", "restore_base_present", "restore", S.FAILED, msg,
                     details={"suggested_base_paths": candidates})
            return None
        return base

    def layer_database(self) -> dict[str, pg_checks.PostgresInstance | None]:
        spec = self.defn.spec
        instances: dict[str, pg_checks.PostgresInstance | None] = {}
        db_checks = [(i, c) for i, c in enumerate(spec.checks) if c.type in DB_CHECKS or c.type in MYSQL_CHECKS]
        if not spec.resources.databases:
            return instances
        with self.stage("database_validation"):
            env = self._docker_for("database")
            for db in spec.resources.databases:
                if env is None:
                    instances[db.name] = None
                    continue
                self.guard()
                t = time.monotonic()
                starter = mysql_checks.start if db.engine in ("mariadb", "mysql") else pg_checks.start
                inst, recs = starter(env, db, self.base)
                for name, status, msg, det in recs:
                    self.add("database", name, name.split(":")[0], status, msg, details=det,
                             duration_ms=int(det.get("ready_ms") or det.get("duration_ms") or 0))
                instances[db.name] = inst
                self.timings[f"database_start:{db.name}"] = int((time.monotonic() - t) * 1000)
            for i, c in db_checks:
                self.guard()
                runner = mysql_checks.run_check if c.type in MYSQL_CHECKS else pg_checks.run_check
                status, msg, details, ms = timed(lambda c=c, runner=runner: runner(c, self.env, instances.get(c.target)))
                self.add("database", check_label(c, i), c.type, status, msg, required=c.required,
                         details=details, duration_ms=ms)
        return instances

    def layer_application(self) -> None:
        spec = self.defn.spec
        if not spec.resources.services:
            return
        with self.stage("application_validation"):
            env = self._docker_for("application")
            instances: dict[str, http_checks.ServiceInstance | None] = {}
            for svc in spec.resources.services:
                if env is None:
                    instances[svc.name] = None
                    continue
                self.guard()
                inst, (status, msg, details) = http_checks.start(env, svc, self.base)
                instances[svc.name] = inst
                self.add("application", f"service_ready:{svc.name}", "service_ready", status, msg, details=details,
                         duration_ms=int(details.get("ready_ms") or 0))
            for i, c in enumerate(spec.checks):
                if c.type not in APP_CHECKS:
                    continue
                self.guard()
                status, msg, details, ms = timed(lambda c=c: http_checks.run_check(c, self.env, instances.get(c.target)))
                self.add("application", check_label(c, i), c.type, status, msg, required=c.required,
                         details=details, duration_ms=ms)

    def layer_objectives(self) -> None:
        rto = self.defn.spec.objectives.rtoMinutes
        if not rto:
            return
        measured = sum(v for k, v in self.timings.items() if k in ("restore", "database_validation",
                                                                   "application_validation"))
        ok = measured / 60000 <= rto
        self.add("objectives", "rto_measured", "rto", S.PASSED if ok else S.FAILED,
                 f"test recovery took {measured / 60000:.1f} min vs RTO target {rto} min "
                 "(test duration is an indicator, not a guarantee of real recovery time)",
                 required=False, details={"measured_ms": measured, "rto_minutes": rto})

    # -- driver --------------------------------------------------------------------------------------------
    def run(self) -> str:
        self.restore_ok = False
        self.base: Path | None = None
        stop: StopRun | None = None
        try:
            self._load_definition()
            self.layer_recovery_point()
            self.layer_data()
            self.layer_database()
            self.layer_application()
            self.layer_objectives()
        except StopRun as exc:
            stop = exc
        except AdapterError as exc:
            stop = self._adapter_stop(exc)
        except Exception as exc:  # noqa: BLE001 - unknown errors are inconclusive, never a pass
            log.exception("attempt %s crashed", self.attempt_id)
            stop = StopRun(AttemptStatus.INCONCLUSIVE, "internal_error",
                           truncate(self.sanitizer.text(f"{type(exc).__name__}: {exc}"), 1000))
        return self._finalize(stop)

    def _finalize(self, stop: StopRun | None) -> str:
        outcomes = [CheckOutcome(r.status, r.required, r.layer) for r in self.records]
        agg = aggregate(outcomes)
        status = stop.status if stop else agg.status
        if stop and stop.status == AttemptStatus.INCONCLUSIVE and agg.status == AttemptStatus.FAILED:
            status = AttemptStatus.FAILED  # a definite failure already observed outranks a later unknown
        if self.env:
            self.logs.append("\n".join(self.env.log))
        self.timings["total"] = int((time.monotonic() - self.t0) * 1000)

        # 1) Persist evidence needed to understand the run *before* deleting anything.
        evidence_ok = True
        try:
            self._write_artifact("log", "run.log", "\n\n".join(x for x in self.logs if x))
        except OSError as exc:
            evidence_ok = False
            log.error("could not write run log: %s", exc)
        if self.adapter:
            self.adapter.close()

        # 2) Cleanup, tracked independently of the recovery result.
        self.beat("cleanup", force=True)
        t = time.monotonic()
        try:
            cleanup_status, problems = cleanup_attempt(self.attempt_id)
        except Exception as exc:  # noqa: BLE001
            cleanup_status, problems = CleanupStatus.FAILED, [{"resource_type": "unknown", "external_id": "",
                                                               "error": truncate(str(exc), 500)}]
        self.timings["cleanup"] = int((time.monotonic() - t) * 1000)

        # 3) Sealed manifest + HTML report.
        finished = utcnow()
        manifest = self._manifest(status, agg, stop, cleanup_status, problems, finished)
        try:
            key = self.settings.signing_key_file if self.settings.sign_reports else None
            sealed = mf.seal(manifest, key)
            self._write_artifact("manifest", "manifest.json", json.dumps(sealed, indent=2, sort_keys=True,
                                                                         default=str))
            self._write_artifact("report_html", "report.html", render_html(sealed))
        except Exception as exc:  # noqa: BLE001
            evidence_ok = False
            sealed = manifest
            log.error("could not persist report: %s", exc)

        job_status = JobStatus(status.value) if status != AttemptStatus.INTERRUPTED else JobStatus.INCONCLUSIVE
        error_code = stop.code if stop else None
        self._last_error_code = error_code
        error_message = str(stop) if stop else None
        if not evidence_ok:
            # We cannot claim a durably recorded result.
            job_status, error_code = JobStatus.INCONCLUSIVE, "evidence_persist_failed"
            error_message = "the run finished but its evidence could not be fully written"

        retry = bool(stop and stop.transient and self.attempt_number < self.settings.max_attempts)
        summary = {"recovery_status": status.value, "cleanup_status": str(cleanup_status),
                   "passed_checks": agg.passed, "failed_checks": agg.failed, "error_checks": agg.errored,
                   "skipped_checks": agg.skipped, "layers": sealed.get("layers"),
                   "manifest_sha256": (sealed.get("evidence") or {}).get("manifest_sha256"),
                   "recovery_point": self.point.native_id if self.point else None, "attempt": self.attempt_number,
                   "hint": ERROR_HINTS.get(error_code) if error_code else None,
                   "suggested_base_path": self._inferred_base_path()}
        with session_scope() as s:
            att = s.get(JobAttempt, self.attempt_id)
            assert_attempt_transition(att.status, status)
            att.status, att.finished_at = status, finished
            att.cleanup_status = cleanup_status
            att.evidence_status = "completed" if evidence_ok else "failed"
            att.timings_json, att.stages_json = self.timings, self.stages
            att.error_code, att.error_message = error_code, error_message
            job = s.get(Job, self.job_id)
            if retry:
                queue.requeue_for_retry(s, job, queue.retry_backoff(self.attempt_number))
                job.summary_json = {**summary, "note": "transient failure; retry scheduled"}
            else:
                queue.finish(s, job, job_status, recovery_status=status.value, cleanup_status=str(cleanup_status),
                             summary=summary, error_code=error_code, error_message=error_message)
        if not retry:
            self._send_notifications(job_status, cleanup_status, problems)
        elif cleanup_status == CleanupStatus.FAILED:
            self._send_notifications(None, cleanup_status, problems)
        return job_status.value if not retry else "retry_scheduled"

    def _inferred_base_path(self) -> str | None:
        if not self.defn:
            return None
        pairs = [(r.details["missing_path"], r.details.get("suggestions", [])) for r in self.records
                 if r.details.get("missing_path")]
        for r in self.records:
            if r.name == "restore_base_present" and r.details.get("suggested_base_paths"):
                return r.details["suggested_base_paths"][0]
        return infer_base_path(self.defn.spec.restore.basePath, pairs) if pairs else None

    def _write_artifact(self, kind: str, filename: str, content: str, name: str | None = None) -> None:
        d = self.settings.reports_dir / self.job_id / f"attempt-{self.attempt_number}"
        d.mkdir(parents=True, exist_ok=True)
        path = d / filename
        data = self.sanitizer.text(content).encode() if kind == "log" else content.encode()
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        with session_scope() as s:
            s.add(EvidenceArtifact(attempt_id=self.attempt_id, artifact_type=kind, name=name,
                                   sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
                                   storage_path=str(path)))

    def _manifest(self, status: AttemptStatus, agg, stop: StopRun | None, cleanup_status: str, problems: list,
                  finished: datetime) -> dict[str, Any]:
        spec = self.defn.spec if self.defn else None
        outcomes = [CheckOutcome(r.status, r.required, r.layer) for r in self.records]
        return {
            "schema_version": mf.SCHEMA_VERSION,
            "restoreproof_version": VERSION,
            "run_id": self.attempt_id,
            "job_id": self.job_id,
            "attempt_number": self.attempt_number,
            "trigger": self.job.trigger,
            "application": {"id": self.app.id, "name": self.app.name},
            "source": {"id": self.source.id, "name": self.source.name, "adapter": self.source.adapter},
            "definition": {"version": self.job.definition_version, "sha256": self.job.definition_sha256},
            "recovery_point": {
                "adapter": self.source.adapter,
                "native_id": self.point.native_id if self.point else None,
                "timestamp": self.point.created_at.isoformat() if self.point else None,
                "hostname": self.point.hostname if self.point else None,
                "paths": self.point.paths if self.point else [],
                "selection": {"policy": spec.source.recoveryPoint.policy if spec else None,
                              "reason": self.selection_reason},
            },
            "tool_version": self.tool_version,
            "adapter_guarantees": self.adapter.guarantees if self.adapter else {},
            "isolation": {"mode": "isolated", "destination": "dedicated per-attempt directory",
                          "network": "docker --internal network (no egress, no published ports)"
                          if self.env else "none"},
            "started_at": self.started.isoformat(),
            "finished_at": finished.isoformat(),
            "restore": {"files": self.restored[0] if self.restored else None,
                        "bytes": self.restored[1] if self.restored else None},
            "result": {"status": status.value, "reason": str(stop) if stop else agg.reason,
                       "error_code": stop.code if stop else None, "error_message": str(stop) if stop else None,
                       "checks_passed": agg.passed, "checks_failed": agg.failed, "checks_error": agg.errored,
                       "checks_skipped": agg.skipped},
            "layers": layer_statuses(outcomes),
            "checks": [{"layer": r.layer, "name": r.name, "type": r.check_type, "required": r.required,
                        "status": r.status, "message": r.message, "duration_ms": r.duration_ms,
                        "details": r.details} for r in self.records],
            "timings_ms": self.timings,
            "stages": self.stages,
            "cleanup": {"status": str(cleanup_status), "orphaned_resources": len(problems), "problems": problems},
            "evidence": {},
        }

    def _notify_payload(self, **extra: Any) -> dict[str, Any]:
        return {"application": self.app.name, "app_id": self.app.id, "job_id": self.job_id,
                "run_id": self.attempt_id,
                "report_url": f"{self.settings.base_url}/#/jobs/{self.job_id}",
                "recovery_point": self.point.native_id[:12] if self.point else None, **extra}

    def _send_notifications(self, job_status: JobStatus | None, cleanup_status: str, problems: list) -> None:
        if cleanup_status == CleanupStatus.FAILED:
            notify("cleanup_failed", self._notify_payload(
                cleanup_status=cleanup_status,
                message=f"{len(problems)} temporary resources could not be removed"))
        if job_status is None:
            return
        first_fail = next((r for r in self.records if r.required and r.status in (S.FAILED, S.ERROR)), None)
        payload = self._notify_payload(
            status=job_status.value, cleanup_status=str(cleanup_status),
            message=(f"{first_fail.name}: {first_fail.message}"[:300] if first_fail else None),
            next_step=(ERROR_HINTS.get(self._last_error_code or "") or
                       (first_fail.details.get("hint") if first_fail else None)))
        with session_scope() as s:
            prev = s.scalars(select(Job).where(Job.app_id == self.app.id, Job.id != self.job_id,
                                               Job.finished_at.is_not(None))
                             .order_by(Job.finished_at.desc()).limit(1)).first()
            prev_status = prev.status if prev else None
        if job_status in (JobStatus.FAILED, JobStatus.TIMED_OUT, JobStatus.BLOCKED):
            notify("recovery_failed", payload)
        elif job_status == JobStatus.INCONCLUSIVE:
            notify("recovery_inconclusive", payload)
        elif job_status == JobStatus.PASSED and prev_status and prev_status != JobStatus.PASSED:
            notify("recovered", payload)
        if job_status == JobStatus.TIMED_OUT and prev_status == JobStatus.TIMED_OUT:
            notify("repeated_timeout", payload)
        if any(r.layer == "objectives" and r.status == S.FAILED for r in self.records):
            notify("objective_breached", {**payload, "message": "; ".join(
                r.message for r in self.records if r.layer == "objectives" and r.status == S.FAILED)})


def _flatten_strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _flatten_strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _flatten_strings(v)]
    return []


def _store_points(source_id: str, points: list[RecoveryPointInfo]) -> None:
    with session_scope() as s:
        existing = {rp.native_id: rp for rp in s.scalars(select(RecoveryPoint).where(
            RecoveryPoint.source_id == source_id)).all()}
        seen = set()
        for p in points:
            seen.add(p.native_id)
            row = existing.get(p.native_id)
            if row is None:
                s.add(RecoveryPoint(source_id=source_id, native_id=p.native_id, created_at=p.created_at,
                                    hostname=p.hostname, paths=p.paths, tags=p.tags,
                                    metadata_json=json.loads(json.dumps(p.metadata, default=str))))
            else:
                row.present = True
        for nid, row in existing.items():
            if nid not in seen:
                row.present = False
        src = s.get(BackupSource, source_id)
        src.last_discovered_at = utcnow()


def run_attempt(job_id: str, attempt_id: str) -> str:
    return AttemptRunner(job_id, attempt_id).run()


__all__ = ["run_attempt", "AttemptRunner", "_store_points", "ManagedResource"]

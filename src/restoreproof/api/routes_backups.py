"""Backup module API: destinations (protocol-aware repositories), plans and runs.

Destinations are stored as backup sources, so every destination can also be used by recovery tests.
"""

from __future__ import annotations

import secrets as pysecrets
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.adapters.base import AdapterError
from restoreproof.api.deps import ApiError, current_user, db, default_project, get_or_404, page, require
from restoreproof.backups import engine, hooks as hk, locations
from restoreproof.backups.writer import ResticWriter
from restoreproof.config import get_settings
from restoreproof.db.models import BackupPlan, BackupRun, BackupSource, ProtectedApp, User, utcnow
from restoreproof.scheduler.scheduler import validate_schedule
from restoreproof.security.crypto import load_secret, store_secret

router = APIRouter(prefix="/api/v1", tags=["backups"])


def _errs(exc: ValidationError) -> list[dict]:
    return [{"loc": ".".join(str(x) for x in e["loc"]), "msg": e["msg"]} for e in exc.errors()]


# -- destinations ------------------------------------------------------------------------------------------
class DestinationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$")
    location: dict[str, Any]
    secret: dict[str, str] = {}
    # Leave empty to generate one (shown once). Supply it to connect an existing restic repository.
    repository_password: str | None = Field(default=None, min_length=8, max_length=4096)


def destination_out(src: BackupSource) -> dict[str, Any]:
    loc = (src.config_json or {}).get("location")
    return {"id": src.id, "name": src.name, "type": loc.get("type") if loc else "restic-url",
            "description": locations.describe(locations.parse(loc)) if loc else src.config_json.get("repository"),
            "location": loc, "managed": bool((src.config_json or {}).get("managed")),
            "last_validation_status": src.last_validation_status, "last_validated_at": src.last_validated_at}


@router.get("/destinations/types")
def destination_types(_: User = Depends(current_user)) -> dict:
    return {"types": [
        {"type": "local", "label": "This machine (disk, USB, mounted NAS/NFS)", "secrets": []},
        {"type": "sftp", "label": "Another Linux server / NAS over SSH (SFTP/SCP)", "secrets": ["private_key"]},
        {"type": "smb", "label": "SMB / Windows share / NAS (Synology, QNAP, TrueNAS, Unraid)", "secrets": ["password"]},
        {"type": "webdav", "label": "WebDAV / Nextcloud / ownCloud", "secrets": ["password"]},
        {"type": "ftp", "label": "FTP / FTPS", "secrets": ["password"]},
        {"type": "rest", "label": "restic REST server (HTTP/HTTPS)", "secrets": ["username", "password"]},
        {"type": "s3", "label": "S3-compatible (AWS, MinIO, Wasabi, Garage, Backblaze S3)", "secrets": ["access_key", "secret_key"]},
        {"type": "b2", "label": "Backblaze B2", "secrets": ["account_id", "account_key"]},
        {"type": "gdrive", "label": "Google Drive", "secrets": ["token"]},
    ], "schema": locations.LOCATION.json_schema()}


@router.post("/destinations/scan-host-key")
def scan_host_key(body: dict, _: User = Depends(require("admin"))) -> dict:
    """Show an SFTP server's host key fingerprint so it can be compared with the server before trusting it."""
    try:
        keys = locations.scan_host_keys(str(body.get("host", "")), int(body.get("port") or 22))
    except (ValueError, TypeError) as exc:
        raise ApiError(422, "invalid_host", str(exc)) from exc
    if not keys:
        raise ApiError(502, "no_host_key", "the server did not answer with an SSH host key (is SSH running on that port?)")
    return {"keys": keys, "note": "Compare the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` "
                                  "on the server before saving."}


@router.get("/destinations")
def list_destinations(s: Session = Depends(db), _: User = Depends(current_user)) -> list:
    return [destination_out(x) for x in s.scalars(select(BackupSource).order_by(BackupSource.name)).all()]


@router.post("/destinations", status_code=201)
def create_destination(body: DestinationIn, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    try:
        loc = locations.parse(body.location)
    except ValidationError as exc:
        raise ApiError(422, "invalid_location", "the destination settings are invalid", _errs(exc)) from exc
    allowed = locations.SECRET_FIELDS[loc.type]
    extra = set(body.secret) - allowed
    if extra:
        raise ApiError(422, "invalid_secret", f"unexpected secret fields for {loc.type}: {sorted(extra)}",
                       {"allowed": sorted(allowed)})
    if s.scalar(select(BackupSource).where(BackupSource.name == body.name)):
        raise ApiError(409, "conflict", f"a source or destination named {body.name!r} already exists")
    generated = body.repository_password is None
    repo_pw = body.repository_password or pysecrets.token_urlsafe(24)
    ref = store_secret(s, {"password": repo_pw, "location_secret": body.secret})
    src = BackupSource(project_id=default_project(s).id, name=body.name, adapter="restic",
                       config_json={"location": loc.model_dump(), "managed": True}, secret_ref=ref)
    s.add(src)
    s.flush()
    audit.record(s, "destination.created", actor=user, target_type="source", target_id=src.id,
                 details={"name": body.name, "type": loc.type, "where": locations.describe(loc)})
    out = destination_out(src)
    if generated:
        out["repository_password"] = repo_pw
        out["repository_password_note"] = ("Store this password somewhere safe (a password manager). It is the "
                                           "only way to decrypt these backups without RestoreProof.")
    return out


@router.post("/destinations/{dest_id}/check")
def check_destination(dest_id: str, s: Session = Depends(db), user: User = Depends(require("operator"))) -> dict:
    """Connect, create the repository if it is new, and report free space for local folders."""
    src = get_or_404(s, BackupSource, dest_id, "destination")
    try:
        w = ResticWriter(src.config_json, load_secret(s, src.secret_ref))
    except AdapterError as exc:
        raise ApiError(422, exc.code, str(exc)) from exc
    try:
        ok, code = w.exists()
        created = False
        if not ok and code == "repository_unavailable" and (src.config_json or {}).get("managed"):
            try:
                w.init()
                ok, created = True, True
            except AdapterError as exc:
                code = f"{code}; init failed: {exc}"
    finally:
        w.close()
    loc = (src.config_json or {}).get("location") or {}
    free = None
    if loc.get("type") == "local":
        import shutil as _sh
        du = _sh.disk_usage(engine.existing_ancestor(Path(loc["path"])))
        free = {"free_bytes": du.free, "total_bytes": du.total}
    src.last_validated_at = utcnow()
    src.last_validation_status = "ok" if ok else (code or "failed")
    audit.record(s, "destination.checked", actor=user, target_type="source", target_id=src.id,
                 details={"ok": ok, "created": created})
    return {"ok": ok, "created": created, "code": None if ok else code, "space": free}


# -- plans -------------------------------------------------------------------------------------------------
class Retention(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    last: int = Field(default=0, ge=0, le=1000)
    daily: int = Field(default=7, ge=0, le=1000)
    weekly: int = Field(default=4, ge=0, le=1000)
    monthly: int = Field(default=6, ge=0, le=1000)
    yearly: int = Field(default=0, ge=0, le=100)


class PlanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$")
    paths: list[str] = Field(min_length=1, max_length=100)
    excludes: list[str] = Field(default=[], max_length=200)
    destination_ids: list[str] = Field(min_length=1, max_length=10)
    hooks: list[dict[str, Any]] = []
    retention: Retention = Retention()
    min_free_percent: int = Field(default=10, ge=0, le=90)
    schedule: str = Field(default="0 2 * * *", max_length=100)
    timezone: str = Field(default="UTC", max_length=64)
    enabled: bool = False
    verify_app_ids: list[str] = []


def _validate_plan(s: Session, body: PlanIn) -> None:
    settings = get_settings()
    for p in body.paths:
        if not p.startswith("/") or ".." in Path(p).parts or "\x00" in p:
            raise ApiError(422, "invalid_path", f"backup paths must be absolute, without '..': {p!r}")
        rp = Path(p).resolve()
        for own in (settings.temp_root, settings.reports_dir):
            if rp == own.resolve() or own.resolve() in rp.parents:
                raise ApiError(422, "invalid_path", f"{p} is RestoreProof's own working area")
    for e in body.excludes:
        if e.startswith("-") or "\x00" in e:
            raise ApiError(422, "invalid_exclude", f"invalid exclude pattern {e!r}")
    for d in body.destination_ids:
        if s.get(BackupSource, d) is None:
            raise ApiError(422, "unknown_destination", f"destination {d} does not exist")
    for a in body.verify_app_ids:
        if s.get(ProtectedApp, a) is None:
            raise ApiError(422, "unknown_app", f"application {a} does not exist")
    try:
        parsed = hk.parse(body.hooks)
        hk.validate_outputs(parsed, body.paths)
    except ValidationError as exc:
        raise ApiError(422, "invalid_hooks", "hook settings are invalid", _errs(exc)) from exc
    except ValueError as exc:
        raise ApiError(422, "invalid_hooks", str(exc)) from exc
    try:
        validate_schedule(body.schedule, body.timezone)
    except Exception as exc:  # noqa: BLE001
        raise ApiError(422, "invalid_schedule", str(exc)) from exc


def plan_out(s: Session, p: BackupPlan) -> dict[str, Any]:
    last = s.scalars(select(BackupRun).where(BackupRun.plan_id == p.id).order_by(BackupRun.created_at.desc()).limit(1)).first()
    last_ok = s.scalars(select(BackupRun).where(BackupRun.plan_id == p.id, BackupRun.status == "succeeded")
                        .order_by(BackupRun.finished_at.desc()).limit(1)).first()
    names = {x.id: x.name for x in s.scalars(select(BackupSource).where(BackupSource.id.in_(p.destination_ids))).all()}
    return {"id": p.id, "name": p.name, "paths": p.paths, "excludes": p.excludes,
            "destinations": [{"id": d, "name": names.get(d, "(deleted)")} for d in p.destination_ids],
            "hooks": p.hooks, "retention": p.retention, "min_free_percent": p.min_free_percent,
            "schedule": p.schedule, "timezone": p.timezone, "enabled": p.enabled, "next_run_at": p.next_run_at,
            "verify_app_ids": p.verify_app_ids, "last_run": run_out(last) if last else None,
            "last_success": run_out(last_ok) if last_ok else None}


def run_out(r: BackupRun) -> dict[str, Any]:
    return {"id": r.id, "plan_id": r.plan_id, "status": r.status, "trigger": r.trigger, "decision": r.decision,
            "destination_id": r.destination_id, "snapshot_id": r.snapshot_id, "source_bytes": r.source_bytes,
            "bytes_added": r.bytes_added, "files_new": r.files_new, "files_changed": r.files_changed,
            "duration_ms": r.duration_ms, "retention_result": r.retention_result, "verify_job_ids": r.verify_job_ids,
            "error_code": r.error_code, "error_message": r.error_message, "created_at": r.created_at,
            "started_at": r.started_at, "finished_at": r.finished_at}


@router.get("/backup-plans")
def list_plans(s: Session = Depends(db), _: User = Depends(current_user)) -> list:
    return [plan_out(s, p) for p in s.scalars(select(BackupPlan).order_by(BackupPlan.name)).all()]


@router.post("/backup-plans", status_code=201)
def create_plan(body: PlanIn, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    _validate_plan(s, body)
    if s.scalar(select(BackupPlan).where(BackupPlan.name == body.name)):
        raise ApiError(409, "conflict", f"a backup plan named {body.name!r} exists")
    from restoreproof.scheduler.scheduler import next_after_cron
    p = BackupPlan(project_id=default_project(s).id, **body.model_dump(exclude={"retention"}),
                   retention=body.retention.model_dump())
    p.next_run_at = next_after_cron(p.schedule, p.timezone, utcnow()) if p.enabled else None
    s.add(p)
    s.flush()
    audit.record(s, "backup_plan.created", actor=user, target_type="backup_plan", target_id=p.id,
                 details={"name": p.name, "paths": p.paths, "destinations": p.destination_ids})
    return plan_out(s, p)


@router.put("/backup-plans/{plan_id}")
def update_plan(plan_id: str, body: PlanIn, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    p = get_or_404(s, BackupPlan, plan_id, "backup plan")
    _validate_plan(s, body)
    from restoreproof.scheduler.scheduler import next_after_cron
    for k, v in body.model_dump(exclude={"retention"}).items():
        setattr(p, k, v)
    p.retention = body.retention.model_dump()
    p.next_run_at = next_after_cron(p.schedule, p.timezone, utcnow()) if p.enabled else None
    audit.record(s, "backup_plan.updated", actor=user, target_type="backup_plan", target_id=p.id,
                 details=body.model_dump())
    return plan_out(s, p)


@router.get("/backup-plans/{plan_id}")
def get_plan(plan_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    return plan_out(s, get_or_404(s, BackupPlan, plan_id, "backup plan"))


@router.post("/backup-plans/{plan_id}/run", status_code=202)
def run_plan(plan_id: str, s: Session = Depends(db), user: User = Depends(require("operator"))) -> dict:
    p = get_or_404(s, BackupPlan, plan_id, "backup plan")
    try:
        run, _ = engine.enqueue(s, p, trigger="manual", actor=user)
    except engine.ActiveBackupExists as exc:
        raise ApiError(409, "backup_already_active", "this plan is already backing up", {"run_id": exc.run_id}) from exc
    s.commit()
    return run_out(run)


@router.get("/backup-runs")
def list_runs(plan_id: str | None = None, limit: int = 50, offset: int = 0, s: Session = Depends(db),
              _: User = Depends(current_user)) -> dict:
    limit, offset = page(limit, offset)
    q = select(BackupRun)
    if plan_id:
        q = q.where(BackupRun.plan_id == plan_id)
    total = s.scalar(select(func.count()).select_from(q.subquery()))
    return {"total": total, "items": [run_out(r) for r in s.scalars(q.order_by(BackupRun.created_at.desc())
                                                                     .limit(limit).offset(offset)).all()]}


@router.get("/backup-runs/{run_id}")
def get_run(run_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    r = get_or_404(s, BackupRun, run_id, "backup run")
    out = run_out(r)
    if r.log_path and Path(r.log_path).is_file():
        out["log"] = Path(r.log_path).read_text(errors="replace")[-20000:]
    return out


@router.delete("/destinations/{dest_id}")
def delete_destination(dest_id: str, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    from restoreproof import deletion
    try:
        return deletion.delete_source(s, get_or_404(s, BackupSource, dest_id, "destination"), actor=user)
    except deletion.Blocked as exc:
        raise ApiError(409, exc.code, str(exc), exc.details) from exc


@router.delete("/backup-plans/{plan_id}")
def delete_plan(plan_id: str, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    """Delete a plan and its run history. Snapshots it already made stay in the repository."""
    from restoreproof import deletion
    try:
        return deletion.delete_plan(s, get_or_404(s, BackupPlan, plan_id, "backup plan"), actor=user)
    except deletion.Blocked as exc:
        raise ApiError(409, exc.code, str(exc), exc.details) from exc

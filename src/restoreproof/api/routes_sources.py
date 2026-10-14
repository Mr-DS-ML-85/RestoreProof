from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.adapters.base import AdapterError
from restoreproof.adapters.restic import ALLOWED_BACKEND_ENV, build_adapter
from restoreproof.api.deps import ApiError, current_user, db, default_project, get_or_404, page, require
from restoreproof.api.schemas import SourceIn, SourcePatch
from restoreproof.db.models import BackupSource, RecoveryPoint, User, utcnow
from restoreproof.jobs.recovery import _store_points
from restoreproof.security.crypto import load_secret, store_secret

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


def _describe(src: BackupSource) -> str | None:
    loc = (src.config_json or {}).get("location")
    if not loc:
        return None
    from restoreproof.backups import locations
    return locations.describe(locations.parse(loc))


def source_out(src: BackupSource, points: int | None = None) -> dict[str, Any]:
    return {"id": src.id, "name": src.name, "adapter": src.adapter,
            "repository": src.config_json.get("repository") or _describe(src), "has_credentials": bool(src.secret_ref),
            "is_destination": bool((src.config_json or {}).get("location")),
            "created_at": src.created_at, "updated_at": src.updated_at,
            "last_validated_at": src.last_validated_at, "last_validation_status": src.last_validation_status,
            "last_validation_message": src.last_validation_message, "last_discovered_at": src.last_discovered_at,
            "recovery_points": points}


def _check_env(env: dict[str, str]) -> None:
    bad = set(env) - ALLOWED_BACKEND_ENV
    if bad:
        raise ApiError(422, "invalid_credentials", f"unsupported backend variables: {sorted(bad)}")


@router.get("")
def list_sources(s: Session = Depends(db), _: User = Depends(current_user)) -> list[dict[str, Any]]:
    out = []
    for src in s.scalars(select(BackupSource).order_by(BackupSource.name)).all():
        n = s.scalar(select(func.count()).select_from(RecoveryPoint).where(
            RecoveryPoint.source_id == src.id, RecoveryPoint.present.is_(True)))
        out.append(source_out(src, n))
    return out


@router.post("", status_code=201)
def create_source(body: SourceIn, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    _check_env(body.credentials.env)
    if s.scalar(select(BackupSource).where(BackupSource.name == body.name)):
        raise ApiError(409, "conflict", f"a source named {body.name!r} already exists")
    ref = store_secret(s, body.credentials.model_dump())
    src = BackupSource(project_id=default_project(s).id, name=body.name, adapter=body.adapter,
                       config_json={"repository": body.repository}, secret_ref=ref)
    s.add(src)
    s.flush()
    audit.record(s, "source.created", actor=user, target_type="source", target_id=src.id,
                 details={"name": body.name, "repository": body.repository})
    return source_out(src, 0)


@router.get("/{source_id}")
def get_source(source_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    return source_out(get_or_404(s, BackupSource, source_id, "source"))


@router.patch("/{source_id}")
def patch_source(source_id: str, body: SourcePatch, s: Session = Depends(db),
                 user: User = Depends(require("admin"))) -> dict:
    src = get_or_404(s, BackupSource, source_id, "source")
    changed = []
    if body.name:
        src.name = body.name
        changed.append("name")
    if body.repository:
        src.config_json = {**src.config_json, "repository": body.repository}
        changed.append("repository")
    if body.credentials:
        _check_env(body.credentials.env)
        src.secret_ref = store_secret(s, body.credentials.model_dump(), src.secret_ref)
        changed.append("credentials")
    if changed:
        src.last_validation_status = None
        src.updated_at = utcnow()
    audit.record(s, "source.updated", actor=user, target_type="source", target_id=src.id,
                 details={"changed": changed})
    return source_out(src)


def _adapter(s: Session, src: BackupSource):
    try:
        return build_adapter(src.adapter, src.config_json, load_secret(s, src.secret_ref))
    except AdapterError as exc:
        raise ApiError(422, exc.code, str(exc)) from exc


@router.post("/{source_id}/validate")
def validate_source(source_id: str, s: Session = Depends(db), user: User = Depends(require("operator"))) -> dict:
    src = get_or_404(s, BackupSource, source_id, "source")
    ad = _adapter(s, src)
    try:
        res = ad.validate_credentials()
        version = ad.tool_version()
    finally:
        ad.close()
    src.last_validated_at = utcnow()
    src.last_validation_status = "ok" if res.ok else res.details.get("code", "failed")
    src.last_validation_message = res.message
    audit.record(s, "source.validated", actor=user, target_type="source", target_id=src.id,
                 details={"ok": res.ok, "code": res.details.get("code")})
    return {"ok": res.ok, "code": None if res.ok else res.details.get("code"), "message": res.message,
            "tool_version": version, "duration_ms": res.duration_ms}


@router.post("/{source_id}/discover")
def discover(source_id: str, s: Session = Depends(db), user: User = Depends(require("operator"))) -> dict:
    src = get_or_404(s, BackupSource, source_id, "source")
    ad = _adapter(s, src)
    try:
        points = ad.list_recovery_points()
    except AdapterError as exc:
        raise ApiError(502, exc.code, str(exc)) from exc
    finally:
        ad.close()
    s.commit()  # release our transaction before the helper opens its own
    _store_points(src.id, points)
    audit.record(s, "source.discovered", actor=user, target_type="source", target_id=src.id,
                 details={"count": len(points)})
    return {"count": len(points), "latest": points[-1].created_at if points else None}


@router.get("/{source_id}/recovery-points")
def recovery_points(source_id: str, limit: int = 50, offset: int = 0, include_missing: bool = False,
                    s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    get_or_404(s, BackupSource, source_id, "source")
    limit, offset = page(limit, offset)
    q = select(RecoveryPoint).where(RecoveryPoint.source_id == source_id)
    if not include_missing:
        q = q.where(RecoveryPoint.present.is_(True))
    total = s.scalar(select(func.count()).select_from(q.subquery()))
    rows = s.scalars(q.order_by(RecoveryPoint.created_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [
        {"id": r.id, "native_id": r.native_id, "created_at": r.created_at, "hostname": r.hostname,
         "paths": r.paths, "tags": r.tags, "present": r.present, "metadata": r.metadata_json} for r in rows]}


@router.get("/{source_id}/usage")
def source_usage(source_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    from restoreproof import deletion
    return deletion.source_dependents(s, get_or_404(s, BackupSource, source_id, "source"))


@router.delete("/{source_id}")
def delete_source(source_id: str, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    """Remove a source/destination from RestoreProof. The backups stored in the repository are not touched."""
    from restoreproof import deletion
    try:
        return deletion.delete_source(s, get_or_404(s, BackupSource, source_id, "source"), actor=user)
    except deletion.Blocked as exc:
        raise ApiError(409, exc.code, str(exc), exc.details) from exc


@router.get("/{source_id}/browse")
def browse(source_id: str, path: str = "/", snapshot: str = "latest", s: Session = Depends(db),
           _: User = Depends(require("operator"))) -> dict:
    """List one folder of a snapshot, so tests can be set up by picking real files instead of typing paths."""
    src = get_or_404(s, BackupSource, source_id, "source")
    ad = _adapter(s, src)
    try:
        return ad.list_dir(snapshot, path)
    except AdapterError as exc:
        raise ApiError(422 if exc.code == "invalid_argument" else 502, exc.code, str(exc)) from exc
    finally:
        ad.close()

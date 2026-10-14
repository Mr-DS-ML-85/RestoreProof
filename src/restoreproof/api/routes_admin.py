"""Setup, authentication, users, notifications, audit, workers, overview."""

from __future__ import annotations

import shutil
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.api.deps import ApiError, current_user, db, default_project, get_or_404, page, require
from restoreproof.api.routes_apps import app_out
from restoreproof.api.schemas import LoginIn, NotificationIn, SetupIn, UserIn
from restoreproof.auth.security import hash_password, issue_token, login_limiter, token_hash, verify_password
from restoreproof.config import get_settings
from restoreproof.db.models import (
    ApiToken,
    AuditEvent,
    Job,
    JobAttempt,
    ManagedResource,
    NotificationEndpoint,
    Policy,
    ProtectedApp,
    User,
    WorkerRecord,
    utcnow,
)
from restoreproof.notifications.dispatch import EVENTS, notify
from restoreproof.security.crypto import store_secret
from restoreproof.security.paths import dir_usage

router = APIRouter(prefix="/api/v1", tags=["admin"])


@router.get("/setup")
def setup_status(s: Session = Depends(db)) -> dict:
    return {"needs_setup": not s.scalar(select(func.count()).select_from(User))}


@router.post("/setup", status_code=201)
def setup(body: SetupIn, request: Request, s: Session = Depends(db)) -> dict:
    if not login_limiter.allow(f"setup:{request.client.host if request.client else '?'}"):
        raise ApiError(429, "rate_limited", "too many attempts")
    if s.scalar(select(func.count()).select_from(User)):
        raise ApiError(409, "already_set_up", "an administrator already exists")
    user = User(email=body.email.lower(), password_hash=hash_password(body.password), role="admin")
    s.add(user)
    s.flush()
    default_project(s).owner_id = user.id
    audit.record(s, "user.created", actor=user, target_type="user", target_id=user.id,
                 details={"role": "admin", "via": "first-run setup"})
    return {"token": issue_token(s, user), "user": {"id": user.id, "email": user.email, "role": user.role}}


@router.post("/auth/login")
def login(body: LoginIn, request: Request, s: Session = Depends(db)) -> dict:
    ip = request.client.host if request.client else "?"
    if not login_limiter.allow(f"login:{ip}") or not login_limiter.allow(f"login-user:{body.email.lower()}"):
        raise ApiError(429, "rate_limited", "too many login attempts; try again later")
    user = s.scalar(select(User).where(User.email == body.email.lower()))
    if user is None or user.disabled or not verify_password(body.password, user.password_hash):
        audit.record(s, "auth.login_failed", details={"email": body.email.lower(), "ip": ip})
        raise ApiError(401, "invalid_login", "email or password is incorrect")
    audit.record(s, "auth.login", actor=user, details={"ip": ip})
    return {"token": issue_token(s, user), "user": {"id": user.id, "email": user.email, "role": user.role}}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, s: Session = Depends(db), _: User = Depends(current_user)) -> None:
    auth = request.headers.get("authorization", "")
    tok = s.scalar(select(ApiToken).where(ApiToken.token_hash == token_hash(auth[7:].strip())))
    if tok:
        s.delete(tok)


@router.get("/auth/me")
def me(user: User = Depends(current_user)) -> dict:
    return {"id": user.id, "email": user.email, "role": user.role}


@router.post("/auth/tokens", status_code=201)
def create_api_token(body: dict, s: Session = Depends(db), user: User = Depends(require("operator"))) -> dict:
    """Long-lived token for automation (CI, cron). Shown once."""
    name = str(body.get("name") or "api")[:100]
    token = issue_token(s, user, name=name, hours=None)
    audit.record(s, "auth.token_created", actor=user, target_type="user", target_id=user.id, details={"name": name})
    return {"token": token, "name": name}


@router.get("/users")
def list_users(s: Session = Depends(db), _: User = Depends(require("admin"))) -> list:
    return [{"id": u.id, "email": u.email, "role": u.role, "disabled": u.disabled, "created_at": u.created_at}
            for u in s.scalars(select(User).order_by(User.created_at)).all()]


@router.post("/users", status_code=201)
def create_user(body: UserIn, s: Session = Depends(db), admin: User = Depends(require("admin"))) -> dict:
    if s.scalar(select(User).where(User.email == body.email.lower())):
        raise ApiError(409, "conflict", "a user with that email exists")
    u = User(email=body.email.lower(), password_hash=hash_password(body.password), role=body.role)
    s.add(u)
    s.flush()
    audit.record(s, "user.created", actor=admin, target_type="user", target_id=u.id, details={"role": body.role})
    return {"id": u.id, "email": u.email, "role": u.role}


# -- notifications -------------------------------------------------------------------------------------------
def _ep_out(e: NotificationEndpoint) -> dict:
    return {"id": e.id, "name": e.name, "type": e.type, "config": e.config_json, "events": e.events,
            "enabled": e.enabled, "has_secret": bool(e.secret_ref), "last_delivery_status": e.last_delivery_status}


def _validate_ep(body: NotificationIn) -> None:
    unknown = set(body.events) - set(EVENTS) - {"*"}
    if unknown:
        raise ApiError(422, "invalid_events", f"unknown events {sorted(unknown)}", {"allowed": EVENTS})
    c, sec = body.config, body.secret
    if body.type == "webhook" and not (sec.get("url") or "").startswith(("http://", "https://")):
        raise ApiError(422, "invalid_config", "webhook needs secret.url (http/https); it is stored encrypted")
    if body.type == "ntfy" and not (sec.get("topic") or c.get("topic")):
        raise ApiError(422, "invalid_config", "ntfy needs a topic (secret.topic recommended)")
    if body.type == "email" and not (c.get("host") and c.get("from") and isinstance(c.get("to"), list)):
        raise ApiError(422, "invalid_config", "email needs config.host, config.from and config.to (list)")
    for k in ("password", "token", "url", "bearer_token"):
        if k in c:
            raise ApiError(422, "invalid_config", f"'{k}' belongs in 'secret', not 'config'")


@router.get("/notifications")
def list_notifications(s: Session = Depends(db), _: User = Depends(require("admin"))) -> dict:
    return {"events": EVENTS, "items": [_ep_out(e) for e in s.scalars(select(NotificationEndpoint)).all()]}


@router.post("/notifications", status_code=201)
def create_notification(body: NotificationIn, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    _validate_ep(body)
    ep = NotificationEndpoint(project_id=default_project(s).id, name=body.name, type=body.type,
                              config_json=body.config, events=body.events, enabled=body.enabled,
                              secret_ref=store_secret(s, body.secret) if body.secret else None)
    s.add(ep)
    s.flush()
    audit.record(s, "notification.created", actor=user, target_type="notification", target_id=ep.id,
                 details={"name": body.name, "type": body.type, "events": body.events})
    return _ep_out(ep)


@router.delete("/notifications/{ep_id}", status_code=204)
def delete_notification(ep_id: str, s: Session = Depends(db), user: User = Depends(require("admin"))) -> None:
    ep = get_or_404(s, NotificationEndpoint, ep_id, "notification endpoint")
    ep.enabled = False  # keep the row for the audit trail
    audit.record(s, "notification.disabled", actor=user, target_type="notification", target_id=ep.id)


@router.post("/notifications/{ep_id}/test")
def test_notification(ep_id: str, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    get_or_404(s, NotificationEndpoint, ep_id, "notification endpoint")
    s.commit()
    res = notify("test", {"message": f"test notification requested by {user.email}"}, endpoint_id=ep_id)
    return {"results": res}


# -- audit / workers / overview -----------------------------------------------------------------------------
@router.get("/audit-events")
def audit_events(action: str | None = None, target_id: str | None = None, limit: int = 100, offset: int = 0,
                 s: Session = Depends(db), _: User = Depends(require("admin"))) -> dict:
    limit, offset = page(limit, offset)
    q = select(AuditEvent)
    if action:
        q = q.where(AuditEvent.action.like(f"{action}%"))
    if target_id:
        q = q.where(AuditEvent.target_id == target_id)
    total = s.scalar(select(func.count()).select_from(q.subquery()))
    rows = s.scalars(q.order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [{"id": e.id, "actor": e.actor_label, "action": e.action,
                                       "target_type": e.target_type, "target_id": e.target_id,
                                       "details": e.details_json, "created_at": e.created_at} for e in rows]}


@router.get("/workers")
def workers(s: Session = Depends(db), _: User = Depends(current_user)) -> list:
    st = get_settings()
    cutoff = utcnow() - timedelta(seconds=max(st.stale_attempt_seconds, st.heartbeat_seconds * 6))
    rows = s.scalars(select(WorkerRecord).order_by(WorkerRecord.heartbeat_at.desc())).all()
    any_online = any(w.heartbeat_at >= cutoff for w in rows)
    # Records of workers replaced by a restart are shown as "retired" rather than as an outage.
    return [{"id": w.id, "hostname": w.hostname, "version": w.version, "started_at": w.started_at,
             "heartbeat_at": w.heartbeat_at, "online": w.heartbeat_at >= cutoff,
             "state": "online" if w.heartbeat_at >= cutoff else ("retired" if any_online else "offline"),
             "note": w.status_note if w.heartbeat_at >= cutoff else None}
            for w in rows]


@router.get("/overview")
def overview(s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    st = get_settings()
    now = utcnow()
    apps = [app_out(s, a) for a in s.scalars(select(ProtectedApp).where(ProtectedApp.archived.is_(False))
                                              .order_by(ProtectedApp.name)).all()]
    for a in apps:
        pol = a["policy"] or {}
        max_age = timedelta(hours=pol.get("max_age_last_success_hours") or 48)
        lp = a["last_passed_job"]
        latest = a["latest_job"]
        a["freshness"] = ("untested" if latest is None else
                          "never_passed" if lp is None else
                          "fresh" if now - lp["finished_at"] <= max_age else "overdue")
    cleanup_warnings = s.scalar(select(func.count()).select_from(ManagedResource)
                                .where(ManagedResource.cleanup_status == "cleanup_failed"))
    upcoming = s.execute(select(Policy, ProtectedApp).join(ProtectedApp, ProtectedApp.id == Policy.app_id)
                         .where(Policy.enabled.is_(True), Policy.next_run_at.is_not(None))
                         .order_by(Policy.next_run_at).limit(10)).all()
    recent = s.scalars(select(Job).order_by(Job.created_at.desc()).limit(15)).all()
    temp_files, temp_bytes = dir_usage(st.temp_root) if st.temp_root.exists() else (0, 0)
    du = shutil.disk_usage(st.temp_root) if st.temp_root.exists() else None
    running = s.scalar(select(func.count()).select_from(JobAttempt).where(JobAttempt.status == "running"))
    cutoff = now - timedelta(seconds=max(st.stale_attempt_seconds, st.heartbeat_seconds * 6))
    ws = s.scalars(select(WorkerRecord)).all()
    return {
        "apps": apps,
        "counts": {"apps": len(apps), "fresh": sum(a["freshness"] == "fresh" for a in apps),
                   "overdue": sum(a["freshness"] == "overdue" for a in apps),
                   "failing": sum((a["latest_job"] or {}).get("status") in ("failed", "timed_out", "blocked",
                                                                           "inconclusive") for a in apps),
                   "untested": sum(a["freshness"] == "untested" for a in apps), "running": running},
        "cleanup_warnings": cleanup_warnings,
        "upcoming": [{"app_id": a.id, "app_name": a.name, "next_run_at": p.next_run_at} for p, a in upcoming],
        "recent_jobs": [{"id": j.id, "app_id": j.app_id, "status": j.status, "cleanup_status": j.cleanup_status,
                         "created_at": j.created_at, "finished_at": j.finished_at, "trigger": j.trigger}
                        for j in recent],
        "temporary_storage": {"files": temp_files, "bytes": temp_bytes, "free_bytes": du.free if du else None},
        "workers": {"total": len(ws), "online": sum(w.heartbeat_at >= cutoff for w in ws)},
    }

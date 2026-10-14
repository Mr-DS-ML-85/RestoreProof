"""Notification delivery: webhook, ntfy, email. Payloads never contain secrets or restored data."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy import select

from restoreproof.db.models import NotificationEndpoint
from restoreproof.db.session import session_scope
from restoreproof.evidence.sanitization import truncate
from restoreproof.security.crypto import load_secret

log = logging.getLogger(__name__)

EVENTS = ("recovery_failed", "recovery_inconclusive", "recovered", "test_overdue", "source_failure",
          "repeated_timeout", "cleanup_failed", "worker_offline", "objective_breached", "backup_failed", "test")
PRIORITY = {"cleanup_failed": "high", "recovery_failed": "high", "source_failure": "high",
            "worker_offline": "high", "repeated_timeout": "high", "backup_failed": "high"}


def _title(event: str, payload: dict[str, Any]) -> str:
    app = payload.get("application") or "RestoreProof"
    return {
        "recovery_failed": f"Recovery test FAILED: {app}",
        "recovery_inconclusive": f"Recovery test inconclusive: {app}",
        "recovered": f"Recovery test passing again: {app}",
        "test_overdue": f"Recovery test overdue: {app}",
        "source_failure": f"Backup source problem: {app}",
        "repeated_timeout": f"Recovery test repeatedly timing out: {app}",
        "cleanup_failed": f"Cleanup FAILED, manual attention needed: {app}",
        "worker_offline": "RestoreProof worker offline",
        "objective_breached": f"Recovery objective breached: {app}",
        "backup_failed": f"Backup did not complete: {app}",
        "test": "RestoreProof test notification",
    }.get(event, f"RestoreProof: {event}")


def _body(event: str, payload: dict[str, Any]) -> str:
    lines = [_title(event, payload)]
    for k in ("status", "recovery_status", "cleanup_status", "recovery_point", "message", "next_step",
              "report_url", "run_id"):
        if payload.get(k):
            lines.append(f"{k}: {payload[k]}")
    return "\n".join(lines)


def deliver(ep: NotificationEndpoint, secret: dict[str, Any], event: str, payload: dict[str, Any]) -> str:
    cfg = ep.config_json or {}
    if ep.type == "webhook":
        url = secret.get("url") or cfg.get("url")
        headers = {"Content-Type": "application/json", "User-Agent": "RestoreProof"}
        if secret.get("bearer_token"):
            headers["Authorization"] = f"Bearer {secret['bearer_token']}"
        r = httpx.post(url, json={"event": event, "title": _title(event, payload), **payload}, headers=headers,
                       timeout=10, follow_redirects=False)
        r.raise_for_status()
        return f"HTTP {r.status_code}"
    if ep.type == "ntfy":
        server = (cfg.get("server") or "https://ntfy.sh").rstrip("/")
        headers = {"Title": _title(event, payload), "Priority": PRIORITY.get(event, "default"),
                   "Tags": "rotating_light" if event in PRIORITY else "floppy_disk"}
        if payload.get("report_url"):
            headers["Click"] = payload["report_url"]
        if secret.get("token"):
            headers["Authorization"] = f"Bearer {secret['token']}"
        r = httpx.post(f"{server}/{secret.get('topic') or cfg['topic']}", content=_body(event, payload).encode(),
                       headers=headers, timeout=10, follow_redirects=False)
        r.raise_for_status()
        return f"HTTP {r.status_code}"
    if ep.type == "email":
        msg = EmailMessage()
        msg["Subject"] = _title(event, payload)
        msg["From"] = cfg["from"]
        msg["To"] = ", ".join(cfg["to"])
        msg.set_content(_body(event, payload))
        port = int(cfg.get("port", 587))
        ctx = ssl.create_default_context()
        if cfg.get("tls", "starttls") == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(cfg["host"], port, timeout=20, context=ctx)
        else:
            smtp = smtplib.SMTP(cfg["host"], port, timeout=20)
            if cfg.get("tls", "starttls") == "starttls":
                smtp.starttls(context=ctx)
        with smtp:
            if cfg.get("username"):
                smtp.login(cfg["username"], secret.get("password", ""))
            smtp.send_message(msg)
        return "sent"
    raise ValueError(f"unknown endpoint type {ep.type}")


def notify(event: str, payload: dict[str, Any], *, endpoint_id: str | None = None) -> list[dict[str, str]]:
    results = []
    with session_scope() as s:
        q = select(NotificationEndpoint).where(NotificationEndpoint.enabled.is_(True))
        if endpoint_id:
            q = select(NotificationEndpoint).where(NotificationEndpoint.id == endpoint_id)
        endpoints = s.scalars(q).all()
        for ep in endpoints:
            if not endpoint_id and event not in (ep.events or []) and "*" not in (ep.events or []):
                continue
            try:
                status = deliver(ep, load_secret(s, ep.secret_ref), event, payload)
            except Exception as exc:  # noqa: BLE001 - delivery problems are recorded, never raised
                status = f"failed: {type(exc).__name__}"
                log.warning("notification %s via %s failed: %s", event, ep.name, truncate(str(exc), 200))
            ep.last_delivery_status = truncate(status, 190)
            results.append({"endpoint": ep.name, "status": status})
    return results

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from restoreproof.db.models import AuditEvent, User
from restoreproof.evidence.sanitization import Sanitizer


def record(session: Session, action: str, *, actor: User | None = None, target_type: str | None = None,
           target_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    """Append-only administrative history. Written in the caller's transaction so a change and its audit
    record commit (or roll back) together. Sensitive-looking keys in details are redacted."""
    session.add(AuditEvent(
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else "system",
        action=action,
        target_type=target_type,
        target_id=target_id,
        details_json=Sanitizer().obj(details or {}),
    ))

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from restoreproof.auth.security import role_at_least, sensitive_limiter, token_hash
from restoreproof.db.models import ApiToken, Project, User, utcnow
from restoreproof.db.session import get_sessionmaker


class ApiError(HTTPException):
    """Structured error: {"error": {"code", "message", "details"}}."""

    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(status_code=status, detail={"code": code, "message": message, "details": details})


def db() -> Iterator[Session]:
    s = get_sessionmaker()()
    try:
        yield s
        s.commit()
    except BaseException:
        s.rollback()
        raise
    finally:
        s.close()


def current_user(authorization: str | None = Header(default=None), s: Session = Depends(db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ApiError(401, "unauthenticated", "a bearer token is required")
    tok = s.scalar(select(ApiToken).where(ApiToken.token_hash == token_hash(authorization[7:].strip())))
    if tok is None or (tok.expires_at and tok.expires_at < utcnow()):
        raise ApiError(401, "unauthenticated", "token is invalid or expired")
    user = s.get(User, tok.user_id)
    if user is None or user.disabled:
        raise ApiError(401, "unauthenticated", "account disabled")
    return user


def require(role: str) -> Callable[..., User]:
    def dep(request: Request, user: User = Depends(current_user)) -> User:
        if not role_at_least(user, role):
            raise ApiError(403, "forbidden", f"this action requires the {role} role")
        if request.method != "GET" and not sensitive_limiter.allow(f"{user.id}"):
            raise ApiError(429, "rate_limited", "too many requests, slow down")
        return user

    return dep


def default_project(s: Session) -> Project:
    p = s.scalar(select(Project).where(Project.name == "default"))
    if p is None:
        p = Project(name="default")
        s.add(p)
        s.flush()
    return p


def get_or_404(s: Session, model: type, ident: str, what: str) -> Any:
    obj = s.get(model, ident)
    if obj is None:
        raise ApiError(404, "not_found", f"{what} {ident} does not exist")
    return obj


def page(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, 200)), max(0, offset)

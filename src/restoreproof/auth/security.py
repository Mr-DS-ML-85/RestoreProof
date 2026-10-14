"""Password hashing (scrypt), opaque bearer tokens (stored hashed), roles, and a login rate limiter."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from sqlalchemy.orm import Session

from restoreproof.db.models import ApiToken, User, utcnow

ROLES = ("viewer", "operator", "admin")
_N, _R, _P = 2**15, 8, 1
SESSION_HOURS = 12


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(session: Session, user: User, name: str = "session", hours: int | None = SESSION_HOURS) -> str:
    token = "rp_" + secrets.token_urlsafe(32)
    session.add(ApiToken(user_id=user.id, token_hash=token_hash(token), name=name,
                         expires_at=utcnow() + timedelta(hours=hours) if hours else None))
    return token


def role_at_least(user: User, role: str) -> bool:
    return ROLES.index(user.role) >= ROLES.index(role)


class RateLimiter:
    def __init__(self, max_events: int, per_seconds: float):
        self.max, self.per = max_events, per_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.per:
                q.popleft()
            if len(q) >= self.max:
                return False
            q.append(now)
            return True


login_limiter = RateLimiter(10, 300)
sensitive_limiter = RateLimiter(30, 60)

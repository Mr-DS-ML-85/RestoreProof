"""Log and message sanitization. Applied before anything is persisted or displayed."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Must run before the key=value rule, which would otherwise redact only the word "Bearer".
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # URL credentials: scheme://user:pass@host
    (re.compile(r"(?P<p>[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@"), r"\g<p>" + REDACTED + "@"),
    # key=value / key: value for sensitive-looking keys
    (re.compile(r"(?i)(?P<k>\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
                r"secret[_-]?key|authorization|cookie|session)\b[\"']?\s*[:=]\s*[\"']?)[^\s\"',;&]+"),
     r"\g<k>" + REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), REDACTED),
]


class Sanitizer:
    def __init__(self, secrets: Iterable[str] = ()):
        # Longest first so a secret containing another secret is fully redacted.
        self._secrets = sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True)

    def add(self, *secrets: str) -> None:
        self._secrets = sorted(set(self._secrets) | {s for s in secrets if s and len(s) >= 4},
                               key=len, reverse=True)

    def text(self, value: str) -> str:
        if not value:
            return value
        for s in self._secrets:
            value = value.replace(s, REDACTED)
        for pat, repl in _PATTERNS:
            value = pat.sub(repl, value)
        return value

    def obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: (REDACTED if _sensitive_key(k) else self.obj(v)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.obj(v) for v in value]
        return value


_SENSITIVE_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)")


def _sensitive_key(key: Any) -> bool:
    return isinstance(key, str) and bool(_SENSITIVE_KEY.search(key))


def truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[: limit // 2] + f"\n…[{len(text) - limit} chars truncated]…\n" + text[-limit // 2:]

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from restoreproof.jobs.state_machine import CheckStatus


@dataclass
class CheckRecord:
    layer: str
    name: str
    check_type: str
    required: bool
    status: str
    message: str
    duration_ms: int = 0
    details: dict[str, Any] = field(default_factory=dict)


def timed(fn: Callable[[], tuple[str, str, dict[str, Any]]]) -> tuple[str, str, dict[str, Any], int]:
    start = time.monotonic()
    try:
        status, message, details = fn()
    except Exception as exc:  # noqa: BLE001 - an exception means the check could not run, not that it failed
        status, message, details = CheckStatus.ERROR, f"check could not run: {type(exc).__name__}: {exc}", {}
    return status, message, details, int((time.monotonic() - start) * 1000)


def compare(actual: Any, expected: Any, op: str) -> bool:
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    try:
        a, e = float(actual), float(expected)
    except (TypeError, ValueError):
        return False
    return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]


@dataclass
class FileContext:
    base: Path

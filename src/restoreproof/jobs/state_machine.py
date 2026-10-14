"""Durable job / attempt state machine and result aggregation (PRD §4, §8.2).

There is deliberately no boolean "success". Recovery outcome and cleanup outcome are tracked separately.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"


class AttemptStatus(StrEnum):
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"
    # The worker vanished (crash, reboot) before finishing. Never treated as a pass.
    INTERRUPTED = "interrupted"


class CleanupStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "cleanup_failed"
    NOT_REQUIRED = "not_required"


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    # The check could not be executed (missing dependency, infrastructure error). Distinct from "failed".
    ERROR = "error"
    SKIPPED = "skipped"


TERMINAL_JOB = frozenset(
    {JobStatus.PASSED, JobStatus.FAILED, JobStatus.INCONCLUSIVE, JobStatus.CANCELLED,
     JobStatus.TIMED_OUT, JobStatus.BLOCKED}
)
TERMINAL_ATTEMPT = frozenset(AttemptStatus) - {AttemptStatus.RUNNING}

JOB_TRANSITIONS: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.QUEUED: frozenset({JobStatus.RUNNING, JobStatus.CANCELLED, JobStatus.BLOCKED}),
    # RUNNING -> QUEUED happens only when an interrupted attempt is scheduled for a bounded retry.
    JobStatus.RUNNING: frozenset(TERMINAL_JOB | {JobStatus.QUEUED}),
}
ATTEMPT_TRANSITIONS: dict[AttemptStatus, frozenset[AttemptStatus]] = {
    AttemptStatus.RUNNING: frozenset(TERMINAL_ATTEMPT),
}
CLEANUP_TRANSITIONS: dict[CleanupStatus, frozenset[CleanupStatus]] = {
    CleanupStatus.PENDING: frozenset({CleanupStatus.COMPLETED, CleanupStatus.FAILED, CleanupStatus.NOT_REQUIRED}),
    # A later reconciliation pass may succeed in removing what an earlier one could not.
    CleanupStatus.FAILED: frozenset({CleanupStatus.COMPLETED, CleanupStatus.FAILED}),
}


class InvalidTransition(Exception):
    pass


def _check(table: dict, current: str, new: str, kind: str) -> None:
    allowed = table.get(current, frozenset())  # StrEnum members hash like their string values
    if new not in allowed:
        raise InvalidTransition(f"{kind}: {current} -> {new} is not allowed")


def assert_job_transition(current: str, new: str) -> None:
    _check(JOB_TRANSITIONS, current, new, "job")


def assert_attempt_transition(current: str, new: str) -> None:
    _check(ATTEMPT_TRANSITIONS, current, new, "attempt")


def assert_cleanup_transition(current: str, new: str) -> None:
    _check(CLEANUP_TRANSITIONS, current, new, "cleanup")


@dataclass(frozen=True)
class CheckOutcome:
    status: str
    required: bool
    layer: str = ""


@dataclass(frozen=True)
class Aggregate:
    status: AttemptStatus
    passed: int
    failed: int
    errored: int
    skipped: int
    reason: str


def aggregate(checks: Iterable[CheckOutcome]) -> Aggregate:
    """Explicit aggregation rule.

    - Any required check failed            -> failed
    - Else any required check error/skipped -> inconclusive (we cannot claim success)
    - Else no required check passed at all  -> inconclusive (nothing meaningful was verified)
    - Else                                  -> passed
    Non-required checks are reported but never decide the outcome.
    """
    checks = list(checks)
    passed = sum(c.status == CheckStatus.PASSED for c in checks)
    failed = sum(c.status == CheckStatus.FAILED for c in checks)
    errored = sum(c.status == CheckStatus.ERROR for c in checks)
    skipped = sum(c.status == CheckStatus.SKIPPED for c in checks)
    req = [c for c in checks if c.required]
    if any(c.status == CheckStatus.FAILED for c in req):
        return Aggregate(AttemptStatus.FAILED, passed, failed, errored, skipped, "a required check failed")
    if any(c.status in (CheckStatus.ERROR, CheckStatus.SKIPPED) for c in req):
        return Aggregate(AttemptStatus.INCONCLUSIVE, passed, failed, errored, skipped,
                         "a required check could not run")
    if not any(c.status == CheckStatus.PASSED for c in req):
        return Aggregate(AttemptStatus.INCONCLUSIVE, passed, failed, errored, skipped,
                         "no required verification check passed")
    return Aggregate(AttemptStatus.PASSED, passed, failed, errored, skipped, "all required checks passed")


def layer_statuses(checks: Iterable[CheckOutcome]) -> dict[str, str]:
    """Per-layer status so a repository pass is not hidden behind an application failure (PRD §4)."""
    by_layer: dict[str, list[CheckOutcome]] = {}
    for c in checks:
        by_layer.setdefault(c.layer, []).append(c)
    out: dict[str, str] = {}
    for layer, items in by_layer.items():
        agg = aggregate(items)
        if agg.status == AttemptStatus.INCONCLUSIVE and not any(c.required for c in items):
            # Only advisory checks in this layer: report the worst observed result.
            out[layer] = "warning" if any(c.status != CheckStatus.PASSED for c in items) else "passed"
        else:
            out[layer] = agg.status.value
    return out

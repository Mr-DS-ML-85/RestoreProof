"""Recovery-point selection (PRD §8.4). Pure functions so every policy is unit-testable.

A moving alias such as "latest" is always resolved to a concrete snapshot id before restoring.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from restoreproof.adapters.base import RecoveryPointInfo
from restoreproof.definitions import RecoveryPointSelection


@dataclass(frozen=True)
class Selection:
    point: RecoveryPointInfo | None
    reason: str
    eligible_count: int


def _matches(p: RecoveryPointInfo, sel: RecoveryPointSelection) -> bool:
    if sel.host and p.hostname != sel.host:
        return False
    if sel.tags and not set(sel.tags).issubset(set(p.tags)):
        return False
    if sel.path and sel.path not in p.paths:
        return False
    return True


def select_recovery_point(points: list[RecoveryPointInfo], sel: RecoveryPointSelection, now: datetime,
                          *, pinned_override: str | None = None, rng: random.Random | None = None) -> Selection:
    if pinned_override or sel.policy == "pinned":
        target = pinned_override or sel.snapshotId or ""
        hits = [p for p in points if p.native_id == target or p.native_id.startswith(target)]
        if len(hits) == 1:
            return Selection(hits[0], f"pinned snapshot {target}", 1)
        if len(hits) > 1:
            return Selection(None, f"pinned id {target} is ambiguous ({len(hits)} matches)", 0)
        return Selection(None, f"pinned snapshot {target} does not exist in the repository", 0)

    eligible = sorted((p for p in points if _matches(p, sel)), key=lambda p: p.created_at)
    if not eligible:
        return Selection(None, "no snapshot matches the host/tag/path filters", 0)

    if sel.policy == "latest":
        return Selection(eligible[-1], "latest matching snapshot", len(eligible))

    if sel.policy == "max_age":
        newest = eligible[-1]
        age = now - newest.created_at
        if age > timedelta(hours=sel.maxAgeHours or 0):
            return Selection(None, f"newest snapshot is {age.total_seconds() / 3600:.1f}h old, "
                                   f"exceeding maxAgeHours={sel.maxAgeHours}", 0)
        return Selection(newest, f"latest snapshot within {sel.maxAgeHours}h", len(eligible))

    if sel.policy == "random":
        if sel.randomWithinDays:
            cutoff = now - timedelta(days=sel.randomWithinDays)
            eligible = [p for p in eligible if p.created_at >= cutoff]
        if not eligible:
            return Selection(None, f"no snapshot within the last {sel.randomWithinDays} days", 0)
        choice = (rng or random.SystemRandom()).choice(eligible)
        return Selection(choice, f"random choice among {len(eligible)} eligible snapshots", len(eligible))

    return Selection(None, f"unknown policy {sel.policy}", 0)

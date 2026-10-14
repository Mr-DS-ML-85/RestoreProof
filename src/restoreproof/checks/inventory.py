"""Inventory check: detects backups that silently shrink or lose files.

Each run records an inventory (relative path -> size, sha256) of the restored tree. An administrator can
approve one run's inventory as the *trusted baseline*. Later runs are compared with it:
  - files from the baseline that are missing   -> fail above maxMissingPercent
  - total size shrinking                       -> fail above maxShrinkPercent
  - files whose content changed                -> reported (fail only when strict)
Without an approved baseline the check records the observation and is advisory for that run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from restoreproof.checks.files import sha256_file
from restoreproof.jobs.state_machine import CheckStatus as S
from restoreproof.security.paths import UnsafePath, resolve_within


class TooManyFiles(Exception):
    pass


def collect(root: Path, max_files: int) -> dict[str, list]:
    out: dict[str, list] = {}
    for dirpath, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for n in sorted(names):
            p = Path(dirpath) / n
            if p.is_symlink() or not p.is_file():
                continue
            if len(out) >= max_files:
                raise TooManyFiles(f"more than {max_files} files under this path")
            out[p.relative_to(root).as_posix()] = [p.stat().st_size, sha256_file(p)]
    return out


def compare_inventories(current: dict[str, list], baseline: dict[str, list]) -> dict[str, Any]:
    missing = sorted(set(baseline) - set(current))
    added = sorted(set(current) - set(baseline))
    changed = sorted(k for k in set(current) & set(baseline) if current[k][1] != baseline[k][1])
    cur_bytes = sum(v[0] for v in current.values())
    base_bytes = sum(v[0] for v in baseline.values())
    return {
        "baseline_files": len(baseline), "current_files": len(current),
        "missing": len(missing), "added": len(added), "changed": len(changed),
        "missing_percent": round(100 * len(missing) / len(baseline), 2) if baseline else 0.0,
        "baseline_bytes": base_bytes, "current_bytes": cur_bytes,
        "shrink_percent": round(100 * (base_bytes - cur_bytes) / base_bytes, 2) if base_bytes and cur_bytes < base_bytes else 0.0,
        "missing_examples": missing[:25], "changed_examples": changed[:25], "added_examples": added[:25],
    }


def run_inventory(check: Any, base: Path, baseline: dict[str, list] | None) -> tuple[str, str, dict, dict | None]:
    """Returns (status, message, details, observation_to_store)."""
    try:
        root = base.resolve() if check.path == "." else resolve_within(base, check.path)
    except UnsafePath as exc:
        return S.FAILED, f"unsafe path rejected: {exc}", {}, None
    if not root.is_dir():
        return S.FAILED, f"{check.path} is missing or not a directory", {"missing_path": check.path}, None
    try:
        current = collect(root, check.maxFiles)
    except TooManyFiles as exc:
        return S.ERROR, f"{exc}; narrow `path` or raise `maxFiles`", {}, None
    total = sum(v[0] for v in current.values())
    observation = {"path": check.path, "files": current}
    if baseline is None:
        return (S.SKIPPED, f"recorded {len(current)} files ({total} bytes). No trusted baseline yet: review this "
                           "run and approve it as the baseline to enable shrinkage detection",
                {"current_files": len(current), "current_bytes": total, "baseline": None}, observation)
    d = compare_inventories(current, baseline)
    problems = []
    if d["missing_percent"] > check.maxMissingPercent:
        problems.append(f"{d['missing']} of {d['baseline_files']} baseline files are missing "
                        f"({d['missing_percent']}% > {check.maxMissingPercent}%)")
    if d["shrink_percent"] > check.maxShrinkPercent:
        problems.append(f"restored data shrank by {d['shrink_percent']}% (> {check.maxShrinkPercent}%)")
    if check.strict and d["changed"]:
        problems.append(f"{d['changed']} files changed content (strict mode)")
    summary = (f"{d['current_files']} files vs baseline {d['baseline_files']}: {d['missing']} missing, "
               f"{d['changed']} changed, {d['added']} new")
    if problems:
        return S.FAILED, "; ".join(problems), d, observation
    return S.PASSED, summary, d, observation


def load_baseline(content: bytes | None, sha256: str) -> dict[str, list]:
    """Decompress a stored baseline and verify it against the hash recorded at approval time."""
    import gzip
    import hashlib

    if not content:
        raise ValueError("baseline has no stored content")
    raw = gzip.decompress(content)
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("baseline content does not match its recorded sha256")
    return json.loads(raw)["files"]

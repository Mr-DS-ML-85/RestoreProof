"""Filesystem safety: every managed path must provably live beneath the temporary root and carry an
ownership marker before RestoreProof will delete it."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from pathlib import Path, PurePosixPath

MARKER_NAME = ".restoreproof-owner.json"
RUN_DIR_RE = re.compile(r"^run-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class UnsafePath(Exception):
    pass


def validate_relative(rel: str) -> PurePosixPath:
    """A user-supplied path inside a restore: relative, no traversal, no NUL, no leading dash."""
    if not rel or "\x00" in rel:
        raise UnsafePath("empty path or NUL byte")
    p = PurePosixPath(rel)
    if p.is_absolute():
        raise UnsafePath(f"absolute paths are not allowed: {rel!r}")
    if any(part == ".." for part in p.parts):
        raise UnsafePath(f"path traversal is not allowed: {rel!r}")
    if rel.startswith("-"):
        raise UnsafePath(f"paths may not start with '-': {rel!r}")
    return p


def resolve_within(root: Path, rel: str, *, allow_symlinks: bool = False) -> Path:
    """Resolve rel beneath root. Symlinks are rejected unless allowed, and even then may not escape root."""
    validate_relative(rel)
    root = root.resolve(strict=True)
    candidate = root.joinpath(rel)
    if not allow_symlinks:
        cur = root
        for part in PurePosixPath(rel).parts:
            cur = cur / part
            if cur.is_symlink():
                raise UnsafePath(f"symbolic link in path: {rel!r}")
    resolved = candidate.resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise UnsafePath(f"path escapes the restore root: {rel!r}")
    return resolved


def create_run_dir(temp_root: Path, attempt_id: str, job_id: str) -> Path:
    temp_root = temp_root.resolve()
    temp_root.mkdir(parents=True, exist_ok=True)
    d = temp_root / f"run-{attempt_id}"
    if not RUN_DIR_RE.match(d.name):
        raise UnsafePath("attempt id is not a UUID")
    # exist_ok=False: a destination is never reused.
    d.mkdir(mode=0o700)
    (d / MARKER_NAME).write_text(json.dumps({"attempt_id": attempt_id, "job_id": job_id}))
    (d / "restore").mkdir(mode=0o700)
    return d


def is_owned_run_dir(temp_root: Path, path: Path, attempt_id: str | None = None) -> bool:
    try:
        temp_root = temp_root.resolve(strict=True)
        if path.is_symlink():
            return False
        path = path.resolve(strict=True)
    except FileNotFoundError:
        return False
    if path.parent != temp_root or not RUN_DIR_RE.match(path.name):
        return False
    marker = path / MARKER_NAME
    if marker.is_symlink() or not marker.is_file():
        return False
    try:
        owner = json.loads(marker.read_text())
    except (OSError, ValueError):
        return False
    if path.name != f"run-{owner.get('attempt_id')}":
        return False
    return attempt_id is None or owner.get("attempt_id") == attempt_id


def safe_remove_run_dir(temp_root: Path, path: Path, attempt_id: str) -> None:
    """Delete a run directory only if it is a tracked, marker-bearing child of temp_root."""
    if not path.exists() and not path.is_symlink():
        return
    if not is_owned_run_dir(temp_root, path, attempt_id):
        raise UnsafePath(f"refusing to delete unowned path {path}")

    def _onexc(func, p, exc):  # type: ignore[no-untyped-def]
        # Restored data may be read-only (e.g. 0444 files, 0555 dirs). Make writable and retry once.
        try:
            parent = os.path.dirname(p)
            os.chmod(parent, os.stat(parent).st_mode | stat.S_IWUSR | stat.S_IXUSR)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR | stat.S_IXUSR)
            func(p)
        except FileNotFoundError:
            pass

    # rmtree does not follow symlinks inside the tree; it unlinks them.
    shutil.rmtree(path, onexc=_onexc)


def dir_usage(path: Path) -> tuple[int, int]:
    """(file_count, total_bytes) without following symlinks."""
    files = total = 0
    for dirpath, _dirs, names in os.walk(path, followlinks=False):
        for n in names:
            try:
                st = os.lstat(os.path.join(dirpath, n))
            except FileNotFoundError:
                continue
            files += 1
            total += st.st_size
    return files, total

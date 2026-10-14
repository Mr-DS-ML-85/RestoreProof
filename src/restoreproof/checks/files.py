"""File integrity checks. Every path is resolved under the restore base; symlinks are rejected."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import yaml

from restoreproof.jobs.state_machine import CheckStatus as S
from restoreproof.security.paths import UnsafePath, resolve_within

MAX_PARSE_BYTES = 32 * 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve(base: Path, rel: str) -> Path:
    return base.resolve() if rel == "." else resolve_within(base, rel)


def run_file_check(check: Any, base: Path) -> tuple[str, str, dict[str, Any]]:
    status, msg, details = _run_file_check(check, base)
    if status == S.FAILED and "missing" in msg and getattr(check, "path", ".") != "." \
            and not (base / check.path).exists():
        details = {**details, "missing_path": check.path}
    return status, msg, details


def _run_file_check(check: Any, base: Path) -> tuple[str, str, dict[str, Any]]:
    try:
        p = _resolve(base, getattr(check, "path", "."))
    except UnsafePath as exc:
        return S.FAILED, f"unsafe path rejected: {exc}", {}
    t = check.type

    if t == "file_exists":
        if not p.exists():
            return S.FAILED, f"{check.path} is missing", {}
        if check.kind == "file" and not p.is_file():
            return S.FAILED, f"{check.path} exists but is not a regular file", {}
        if check.kind == "directory" and not p.is_dir():
            return S.FAILED, f"{check.path} exists but is not a directory", {}
        return S.PASSED, f"{check.path} exists", {"kind": "directory" if p.is_dir() else "file"}

    if t == "file_hash":
        if not p.is_file():
            return S.FAILED, f"{check.path} is missing or not a file", {}
        actual = sha256_file(p)
        ok = actual == check.sha256
        return (S.PASSED if ok else S.FAILED,
                "sha256 matches the expected value" if ok else "sha256 does not match the expected value",
                {"expected": check.sha256, "actual": actual, "size": p.stat().st_size})

    if t == "hash_manifest":
        mismatched, missing = [], []
        for e in check.entries:
            try:
                fp = resolve_within(base, e["path"])
            except UnsafePath:
                missing.append(e["path"])
                continue
            if not fp.is_file():
                missing.append(e["path"])
            elif sha256_file(fp) != e["sha256"]:
                mismatched.append(e["path"])
        ok = not mismatched and not missing
        return (S.PASSED if ok else S.FAILED,
                f"{len(check.entries)} files match the manifest" if ok else
                f"{len(missing)} missing, {len(mismatched)} mismatched of {len(check.entries)}",
                {"missing": missing[:100], "mismatched": mismatched[:100], "total": len(check.entries)})

    if t == "file_size":
        if not p.is_file():
            return S.FAILED, f"{check.path} is missing or not a file", {}
        size = p.stat().st_size
        if check.minBytes is not None and size < check.minBytes:
            return S.FAILED, f"{size} bytes is below the minimum of {check.minBytes}", {"size": size}
        if check.maxBytes is not None and size > check.maxBytes:
            return S.FAILED, f"{size} bytes exceeds the maximum of {check.maxBytes}", {"size": size}
        return S.PASSED, f"size {size} bytes is within bounds", {"size": size}

    if t in ("file_count", "dir_not_empty"):
        if not p.is_dir():
            return S.FAILED, f"{check.path} is missing or not a directory", {}
        count = 0
        pattern = getattr(check, "pattern", None)
        for _dp, _dirs, names in os.walk(p, followlinks=False):
            count += sum(1 for n in names if not pattern or fnmatch.fnmatch(n, pattern))
        if t == "dir_not_empty":
            return (S.PASSED, f"{count} files found", {"count": count}) if count else \
                (S.FAILED, f"{check.path} contains no files", {"count": 0})
        if check.min is not None and count < check.min:
            return S.FAILED, f"{count} files, expected at least {check.min}", {"count": count}
        if check.max is not None and count > check.max:
            return S.FAILED, f"{count} files, expected at most {check.max}", {"count": count}
        return S.PASSED, f"{count} files", {"count": count}

    if t == "file_permissions":
        if not p.exists():
            return S.FAILED, f"{check.path} is missing", {}
        st = p.lstat()
        mode = stat.S_IMODE(st.st_mode)
        details = {"mode": f"{mode:04o}", "uid": st.st_uid, "gid": st.st_gid}
        problems = []
        if check.mode is not None and mode != int(check.mode, 8):
            problems.append(f"mode {mode:04o} != {int(check.mode, 8):04o}")
        if check.uid is not None and st.st_uid != check.uid:
            problems.append(f"uid {st.st_uid} != {check.uid}")
        if check.gid is not None and st.st_gid != check.gid:
            problems.append(f"gid {st.st_gid} != {check.gid}")
        return (S.FAILED, "; ".join(problems), details) if problems else (S.PASSED, "permissions match", details)

    if t == "file_parse":
        if not p.is_file():
            return S.FAILED, f"{check.path} is missing or not a file", {}
        if p.stat().st_size > MAX_PARSE_BYTES:
            return S.ERROR, "file too large to parse safely", {"size": p.stat().st_size}
        raw = p.read_bytes()
        try:
            if check.format == "json":
                json.loads(raw)
            else:
                yaml.safe_load(raw)
        except (ValueError, yaml.YAMLError) as exc:
            return S.FAILED, f"{check.path} is not valid {check.format}: {str(exc)[:200]}", {}
        return S.PASSED, f"{check.path} parses as {check.format}", {"size": len(raw)}

    return S.ERROR, f"unsupported file check {t}", {}

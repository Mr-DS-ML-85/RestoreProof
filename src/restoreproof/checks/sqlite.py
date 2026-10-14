"""SQLite checks for apps such as Vaultwarden, Home Assistant, Gitea, Paperless (SQLite mode).

The restored file is opened read-only. If a write-ahead log (-wal) was restored too, the database and its WAL
are copied into the attempt's scratch area first so committed-but-not-checkpointed data is included; the
original restored copy is never modified. An authorizer denies every statement except reads.
"""

from __future__ import annotations

import shutil
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

from restoreproof.checks.base import compare
from restoreproof.jobs.state_machine import CheckStatus as S
from restoreproof.security.paths import UnsafePath, resolve_within

HEADER = b"SQLite format 3\x00"
_ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_PRAGMA,
            getattr(sqlite3, "SQLITE_RECURSIVE", 33)}
_ALLOWED_PRAGMAS = {"integrity_check", "quick_check", "user_version", "schema_version", "table_info",
                    "page_count", "page_size", "journal_mode"}


def _authorizer(action: int, arg1: Any, arg2: Any, _db: Any, _trigger: Any) -> int:
    if action not in _ALLOWED:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and (arg1 or "").lower() not in _ALLOWED_PRAGMAS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _open(db: Path, scratch: Path, timeout_s: float) -> tuple[sqlite3.Connection, dict[str, Any]]:
    info: dict[str, Any] = {"size": db.stat().st_size}
    with open(db, "rb") as fh:
        if fh.read(16) != HEADER:
            raise ValueError("not an SQLite 3 database (bad header)")
    wal = db.with_name(db.name + "-wal")
    if wal.is_file() and wal.stat().st_size > 0:
        work = scratch / f"sqlite-{uuid.uuid4().hex[:8]}"
        work.mkdir(parents=True)
        shutil.copy2(db, work / db.name)
        shutil.copy2(wal, work / wal.name)
        target, uri_opts = work / db.name, "mode=ro"
        info["wal_applied"] = True
        info["wal_size"] = wal.stat().st_size
    else:
        target, uri_opts = db, "mode=ro&immutable=1"
    conn = sqlite3.connect(f"file:{quote(str(target))}?{uri_opts}", uri=True, timeout=5,
                           check_same_thread=False)
    deadline = time.monotonic() + timeout_s
    conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
    conn.set_authorizer(_authorizer)
    return conn, info


def run_sqlite_check(check: Any, base: Path, scratch: Path, timeout_s: float = 120) -> tuple[str, str, dict]:
    try:
        db = resolve_within(base, check.path)
    except UnsafePath as exc:
        return S.FAILED, f"unsafe path rejected: {exc}", {}
    if not db.is_file():
        return S.FAILED, f"database file {check.path} is missing from the restore", {"missing_path": check.path}
    try:
        conn, info = _open(db, scratch, timeout_s)
    except ValueError as exc:
        return S.FAILED, f"{check.path}: {exc}", {}
    except sqlite3.Error as exc:
        return S.FAILED, f"{check.path} cannot be opened: {exc}", {}
    try:
        if check.type == "sqlite_integrity":
            rows = [r[0] for r in conn.execute(f"PRAGMA {check.mode}").fetchall()]
            info["result"] = rows[:20]
            if rows != ["ok"]:
                return S.FAILED, f"{check.mode} reported {len(rows)} problem(s): {rows[0]}"[:400], info
            missing = []
            for t in check.tables:
                if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone() is None:
                    missing.append(t)
            info["user_version"] = conn.execute("PRAGMA user_version").fetchone()[0]
            if missing:
                return S.FAILED, f"database is intact but expected tables are missing: {', '.join(missing)}", info
            return S.PASSED, f"{check.mode} ok" + (f", {len(check.tables)} expected tables present"
                                                   if check.tables else ""), info
        try:
            row = conn.execute(check.query).fetchone()
        except sqlite3.DatabaseError as exc:
            return S.FAILED, f"query error: {exc}", {"query": check.query}
        actual = row[0] if row else None
        info.update({"query": check.query, "actual": actual, "expected": check.expect, "op": check.op})
        if compare(actual, check.expect, check.op):
            return S.PASSED, f"result {actual!r} {check.op} {check.expect!r}", info
        return S.FAILED, f"result {actual!r} does not satisfy {check.op} {check.expect!r}", info
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc):
            return S.ERROR, f"check exceeded {int(timeout_s)}s", info
        return S.FAILED, f"database error: {exc}", info
    except sqlite3.DatabaseError as exc:
        return S.FAILED, f"database is corrupt: {exc}", info
    finally:
        conn.close()

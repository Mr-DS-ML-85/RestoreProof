"""Pre-backup consistency hooks. Structured, validated operations; there is no free-form shell hook.

- sqlite_backup     consistent copy of a live SQLite database via SQLite's online-backup API
- postgres_dump     pg_dump from a running PostgreSQL container, streamed to a file (optionally gzip)
- pause_container   freeze a container for the duration of the backup (unpaused afterwards, always)
"""

from __future__ import annotations

import gzip
import os
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

from restoreproof.config import get_settings

CONTAINER_RE = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"


class _Hook(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _abs(v: str) -> str:
    if not v.startswith("/") or ".." in Path(v).parts or "\x00" in v:
        raise ValueError("must be an absolute path without '..'")
    return v


class SqliteBackup(_Hook):
    type: Literal["sqlite_backup"]
    source: str
    output: str

    @field_validator("source", "output")
    @classmethod
    def _paths(cls, v: str) -> str:
        return _abs(v)


class PostgresDump(_Hook):
    type: Literal["postgres_dump"]
    container: str = Field(pattern=CONTAINER_RE)
    user: str = Field(default="postgres", pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
    database: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
    output: str
    format: Literal["plain", "custom"] = "plain"
    gzip: bool = False

    @field_validator("output")
    @classmethod
    def _path(cls, v: str) -> str:
        return _abs(v)


class PauseContainer(_Hook):
    type: Literal["pause_container"]
    container: str = Field(pattern=CONTAINER_RE)


Hook = Annotated[Union[SqliteBackup, PostgresDump, PauseContainer], Field(discriminator="type")]
HOOKS = TypeAdapter(list[Hook])


def parse(hooks: list[dict[str, Any]]) -> list[Any]:
    return HOOKS.validate_python(hooks or [])


class HookError(Exception):
    pass


def _inside(path: str, roots: list[str]) -> bool:
    p = Path(path).resolve()
    return any(p == Path(r).resolve() or Path(r).resolve() in p.parents for r in roots)


def validate_outputs(hooks: list[Any], paths: list[str]) -> None:
    """A hook's output must land inside a backed-up path, otherwise it would not be in the snapshot."""
    for h in hooks:
        out = getattr(h, "output", None)
        if out and not _inside(out, paths):
            raise ValueError(f"{h.type}: output {out} is not inside any backed-up path, so it would not be backed up")


def _atomic_target(out: str) -> Path:
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p.with_name(p.name + ".rp-partial")


def run_sqlite_backup(h: SqliteBackup) -> str:
    if not Path(h.source).is_file():
        raise HookError(f"sqlite_backup: {h.source} does not exist")
    tmp = _atomic_target(h.output)
    src = sqlite3.connect(f"file:{h.source}?mode=ro", uri=True, timeout=30)
    dst = sqlite3.connect(tmp)
    try:
        src.backup(dst)  # online backup API: consistent even while the application writes
        ok = dst.execute("PRAGMA quick_check").fetchone()[0]
        if ok != "ok":
            raise HookError(f"sqlite_backup: copy failed quick_check: {ok}")
    finally:
        src.close()
        dst.close()
    os.replace(tmp, h.output)
    return f"sqlite_backup: {h.source} → {h.output} ({Path(h.output).stat().st_size} bytes)"


def run_postgres_dump(h: PostgresDump, timeout: float = 3600) -> str:
    docker = get_settings().docker_binary
    argv = [docker, "exec", h.container, "pg_dump", "-U", h.user, *(["-Fc"] if h.format == "custom" else []), h.database]
    tmp = _atomic_target(h.output)
    start = time.monotonic()
    with open(tmp, "wb") as raw:
        sink = gzip.GzipFile(fileobj=raw, mode="wb") if h.gzip else raw
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        assert proc.stdout is not None
        try:
            shutil.copyfileobj(proc.stdout, sink, 1024 * 1024)
            proc.wait(timeout=max(1, timeout - (time.monotonic() - start)))
        except subprocess.TimeoutExpired:
            proc.kill()
            raise HookError("postgres_dump: timed out") from None
        finally:
            if h.gzip:
                sink.close()
        err = proc.stderr.read().decode(errors="replace")[:500] if proc.stderr else ""
    if proc.returncode != 0:
        tmp.unlink(missing_ok=True)
        # A failed dump must never replace the previous good one.
        raise HookError(f"postgres_dump failed (exit {proc.returncode}): {err.strip()}")
    if tmp.stat().st_size == 0:
        tmp.unlink(missing_ok=True)
        raise HookError("postgres_dump produced an empty file")
    os.replace(tmp, h.output)
    return f"postgres_dump: {h.container}/{h.database} → {h.output} ({Path(h.output).stat().st_size} bytes)"


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([get_settings().docker_binary, *args], capture_output=True, text=True, timeout=120)


def pause(container: str) -> None:
    r = _docker("pause", container)
    if r.returncode != 0:
        raise HookError(f"pause_container: could not pause {container}: {r.stderr.strip()[:200]}")


def unpause(container: str) -> str:
    r = _docker("unpause", container)
    if r.returncode != 0 and "is not paused" not in r.stderr:
        return f"unpause {container} FAILED: {r.stderr.strip()[:200]}"
    return f"unpaused {container}"

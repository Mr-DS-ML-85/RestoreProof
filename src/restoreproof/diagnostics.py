"""`restoreproof doctor` / GET /api/v1/diagnostics: is this installation able to run meaningful tests?"""

from __future__ import annotations

import os
import re
import shutil
import stat
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text

from restoreproof.config import get_settings
from restoreproof.security.process import run_command

MIN_RESTIC = (0, 16, 0)        # verified end to end (Ubuntu 24.04 ships 0.16.4)
RECOMMENDED_RESTIC = (0, 17, 0)  # adds precise exit codes for missing repository / lock / wrong password


def _item(name: str, status: str, detail: str, fix: str = "") -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def run() -> list[dict[str, str]]:
    st = get_settings()
    out: list[dict[str, str]] = []

    try:
        r = run_command([st.restic_binary, "version"], timeout=15)
        m = re.search(r"restic (\d+)\.(\d+)\.(\d+)", r.stdout)
        if not m:
            out.append(_item("restic", "fail", "restic did not report a version", "Install restic ≥ 0.17"))
        elif tuple(map(int, m.groups())) < MIN_RESTIC:
            out.append(_item("restic", "fail", f"restic {'.'.join(m.groups())} is older than 0.16",
                             "Upgrade restic to 0.16 or newer"))
        elif tuple(map(int, m.groups())) < RECOMMENDED_RESTIC:
            out.append(_item("restic", "warn", f"restic {'.'.join(m.groups())} works; 0.17+ is recommended",
                             "Newer restic reports wrong passwords and locked repositories more precisely"))
        else:
            out.append(_item("restic", "ok", r.stdout.strip().split(" compiled")[0]))
    except (FileNotFoundError, PermissionError):
        out.append(_item("restic", "fail", f"{st.restic_binary} not found", "Install restic or set RESTOREPROOF_RESTIC_BINARY"))

    try:
        r = run_command([st.docker_binary, "version", "--format", "{{.Server.Version}}"], timeout=15)
        out.append(_item("docker", "ok" if r.ok else "warn",
                         f"Docker {r.stdout.strip()}" if r.ok else "Docker daemon not reachable",
                         "" if r.ok else "Database and application checks need Docker on the worker host"))
        if r.ok:
            r2 = run_command([st.docker_binary, "image", "inspect", st.http_probe_image], timeout=15)
            if not r2.ok:
                out.append(_item("http probe image", "warn", f"{st.http_probe_image} not present locally",
                                 f"It is pulled on first HTTP check; pre-pull: docker pull {st.http_probe_image}"))
    except (FileNotFoundError, PermissionError):
        out.append(_item("docker", "warn", "docker CLI not found",
                         "Only file and SQLite checks can run without Docker"))

    for label, path in (("temporary restore area", st.temp_root), ("reports", st.reports_dir)):
        if not path.exists():
            out.append(_item(label, "fail", f"{path} does not exist", "Create it or check RESTOREPROOF_DATA_DIR"))
        elif not os.access(path, os.W_OK):
            out.append(_item(label, "warn", f"{path} is not writable by this process",
                             "Only the worker needs to write here"))
        else:
            du = shutil.disk_usage(path)
            level = "ok" if du.free > st.min_free_bytes * 3 else "warn"
            out.append(_item(label, level, f"{path}: {du.free / 1024**3:.1f} GiB free",
                             "" if level == "ok" else "Free space is close to the safety threshold"))

    kf = st.secret_key_file
    if not kf.exists():
        out.append(_item("credential key", "warn", "not created yet (created on first use)",
                         "Create it explicitly with `restoreproof gen-key` and back it up"))
    else:
        mode = stat.S_IMODE(kf.stat().st_mode)
        # 0640 with a dedicated group (native install) is fine; anything readable by "other" is not.
        exposed = bool(mode & 0o007) or bool(mode & 0o020)
        out.append(_item("credential key", "warn" if exposed else "ok", f"{kf} mode {mode:04o}",
                         "chmod 600 (or 640 with a dedicated group): other users can read this key" if exposed
                         else "Make sure this file is backed up separately from the database"))

    try:
        from restoreproof.db.models import WorkerRecord
        from restoreproof.db.session import get_engine, session_scope
        from restoreproof.db.models import utcnow
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
            rev = c.execute(text("SELECT version_num FROM alembic_version")).scalar()
        out.append(_item("metadata database", "ok", f"{get_engine().dialect.name}, schema {rev}"))
        if get_engine().dialect.name == "sqlite":
            out.append(_item("database engine", "warn", "SQLite metadata database",
                             "Fine for one host; use PostgreSQL (RESTOREPROOF_DATABASE_URL) for production"))
        with session_scope() as s:
            cutoff = utcnow() - timedelta(seconds=max(st.stale_attempt_seconds, st.heartbeat_seconds * 6))
            ws = s.scalars(select(WorkerRecord)).all()
            online = [w for w in ws if w.heartbeat_at >= cutoff]
            out.append(_item("workers", "ok" if online else "fail",
                             f"{len(online)} of {len(ws)} online",
                             "" if online else "Start `restoreproof worker`; queued tests will not run without one"))
    except Exception as exc:  # noqa: BLE001
        out.append(_item("metadata database", "fail", f"{type(exc).__name__}", "Check RESTOREPROOF_DATABASE_URL and run `restoreproof migrate`"))
    return out


def summary(items: list[dict[str, Any]]) -> str:
    return "fail" if any(i["status"] == "fail" for i in items) else "warn" if any(
        i["status"] == "warn" for i in items) else "ok"

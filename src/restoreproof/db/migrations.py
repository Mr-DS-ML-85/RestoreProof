"""Run Alembic migrations programmatically (on API/worker start-up and via `restoreproof migrate`).

The API, worker and scheduler may start at the same moment, so migrations are serialized: a file lock in the
data directory (single host) plus a PostgreSQL advisory lock taken inside env.py (multiple hosts).
"""

from __future__ import annotations

import fcntl
from pathlib import Path

from alembic import command
from alembic.config import Config

from restoreproof.config import get_settings

SCRIPTS = Path(__file__).resolve().parent.parent / "migrations"
ADVISORY_LOCK_ID = 727_001


def alembic_config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPTS))
    cfg.set_main_option("sqlalchemy.url", (url or get_settings().database_url).replace("%", "%%"))
    return cfg


def upgrade(url: str | None = None) -> None:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    with open(settings.data_dir / ".migrate.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            command.upgrade(alembic_config(url), "head")
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

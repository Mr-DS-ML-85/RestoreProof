from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HAS_RESTIC = shutil.which("restic") is not None


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


HAS_DOCKER = _docker_ok()


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated settings + fresh migrated SQLite database for every test."""
    from restoreproof.db.session import reset_caches

    data = tmp_path / "data"
    monkeypatch.setenv("RESTOREPROOF_DATA_DIR", str(data))
    monkeypatch.setenv("RESTOREPROOF_MIN_FREE_BYTES", str(10 * 1024 * 1024))
    monkeypatch.setenv("RESTOREPROOF_STALE_ATTEMPT_SECONDS", "60")
    monkeypatch.setenv("RESTOREPROOF_HEARTBEAT_SECONDS", "2")
    monkeypatch.setenv("RESTOREPROOF_WORKER_ID", "test-worker")
    pg_admin = os.environ.get("RESTOREPROOF_TEST_PG_URL")
    if pg_admin:
        # Fresh PostgreSQL database per test, e.g. RESTOREPROOF_TEST_PG_URL=postgresql+psycopg://u:p@host/postgres
        import uuid

        from sqlalchemy import create_engine, text
        name = f"rp_test_{uuid.uuid4().hex[:12]}"
        eng = create_engine(pg_admin, isolation_level="AUTOCOMMIT")
        with eng.connect() as conn:
            conn.execute(text(f"CREATE DATABASE {name}"))
        eng.dispose()
        monkeypatch.setenv("RESTOREPROOF_DATABASE_URL", pg_admin.rsplit("/", 1)[0] + "/" + name)
    reset_caches()
    from restoreproof.auth.security import login_limiter, sensitive_limiter
    login_limiter._hits.clear()
    sensitive_limiter._hits.clear()
    from restoreproof.config import ensure_dirs, get_settings
    from restoreproof.db.migrations import upgrade

    ensure_dirs(get_settings())
    upgrade()
    from restoreproof.jobs import queue
    queue.register_worker("test-worker", "test", "test")
    yield get_settings()
    reset_caches()


REPO_PASSWORD = "correct horse battery staple"


def _restic(repo: Path, *args: str, cwd: Path | None = None, password: str = REPO_PASSWORD) -> str:
    r = subprocess.run(["restic", "-r", str(repo), *args], capture_output=True, text=True, cwd=cwd,
                       env={**os.environ, "RESTIC_PASSWORD": password, "RESTIC_CACHE_DIR": str(repo) + "-cache"},
                       timeout=120)
    assert r.returncode == 0, r.stderr
    return r.stdout


@pytest.fixture
def restic_repo(tmp_path):
    """A real encrypted restic repository with one snapshot of a known dataset. Returns (repo, src, snapshot_id)."""
    if not HAS_RESTIC:
        pytest.skip("restic not installed")
    repo, src = tmp_path / "repo", tmp_path / "app"
    (src / "data").mkdir(parents=True)
    (src / "data" / "important.json").write_text(json.dumps({"users": 3}))
    (src / "data" / "notes.txt").write_text("hello restore\n")
    (src / "config.yaml").write_text("db: postgres\n")
    os.chmod(src / "config.yaml", 0o640)
    _restic(repo, "init")
    out = _restic(repo, "backup", "--json", "--host", "testhost", "--tag", "app", ".", cwd=src)
    snap = [json.loads(line) for line in out.splitlines() if '"summary"' in line][-1]["snapshot_id"]
    return repo, src, snap


def restic(repo: Path, *args: str, cwd: Path | None = None) -> str:
    return _restic(repo, *args, cwd=cwd)

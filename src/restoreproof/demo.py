"""Demo data: a small fake app, a real restic backup of it, a source and a recovery test, so a first-time user
sees a real result in a minute. `break_demo` makes a damaged backup, to show what a failure looks like."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import subprocess
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.config import get_settings
from restoreproof.db.models import BackupSource, ProtectedApp, User

SOURCE_NAME, APP_NAME = "demo-backups", "demo-notes"


class DemoError(Exception):
    pass


def _paths() -> tuple[Path, Path, Path]:
    root = get_settings().data_dir / "demo"
    return root, root / "notes-app", root / "repo"


def _restic(repo: Path, password: str, *args: str, cwd: Path | None = None) -> None:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RESTIC_PASSWORD": password,
           "RESTIC_CACHE_DIR": str(get_settings().data_dir / "cache" / "restic"), "HOME": os.environ.get("HOME", "/tmp")}
    r = subprocess.run([get_settings().restic_binary, "-r", str(repo), *args], cwd=cwd, env=env,
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise DemoError(f"restic {args[0]} failed: {r.stderr.strip()[-300:]}")


def _make_app_files(app: Path) -> None:
    (app / "notes").mkdir(parents=True, exist_ok=True)
    for i, title in enumerate(["Shopping list", "Wi-Fi password hint", "Holiday plans", "Recipes", "Car service"]):
        (app / "notes" / f"note-{i + 1}.md").write_text(f"# {title}\n\nThis is a demo note.\n")
    (app / "settings.json").write_text(json.dumps({"theme": "dark", "version": 3}, indent=2))
    (app / "notes.db").unlink(missing_ok=True)  # replace, never open, a possibly damaged file
    db = sqlite3.connect(app / "notes.db")
    db.executescript("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
    db.executemany("INSERT INTO notes (title) VALUES (?)", [(f"note {i}",) for i in range(1, 6)])
    db.commit()
    db.close()


DEFINITION = """# Demo test: a small notes app (5 notes, a settings file and a SQLite database).
apiVersion: restoreproof.io/v1alpha1
kind: RecoveryTest
metadata:
  name: demo-notes
  description: Demo app created by "Try it with demo data"
spec:
  source:
    recoveryPoint: latest
  restore:
    maxDurationSeconds: 300
    basePath: "."
  checks:
    - {type: file_exists, path: settings.json, kind: file}
    - {type: file_parse, path: settings.json, format: json}
    - {type: file_count, path: notes, min: 5, name: all-notes-present}
    - {type: sqlite_integrity, path: notes.db, tables: [notes]}
    - {type: sqlite_query, path: notes.db, name: notes-in-database, query: "SELECT count(*) FROM notes", expect: 5, op: gte}
"""


def create(s: Session, user: User | None) -> dict:
    from restoreproof.api.deps import default_project
    from restoreproof.db.models import Policy, TestDefinitionVersion
    from restoreproof.definitions import definition_sha256
    from restoreproof.security.crypto import store_secret

    existing = s.scalar(select(ProtectedApp).where(ProtectedApp.name == APP_NAME, ProtectedApp.deleted_at.is_(None)))
    if existing:
        return {"app_id": existing.id, "source_id": existing.source_id, "created": False}
    root, app_dir, repo = _paths()
    try:
        root.mkdir(parents=True, exist_ok=True)
        if not os.access(root, os.W_OK):
            raise PermissionError(root)
    except PermissionError as exc:
        raise DemoError("this process cannot write demo data. With Docker run: "
                        "docker compose exec worker restoreproof demo") from exc
    password = secrets.token_urlsafe(18)
    _make_app_files(app_dir)
    if repo.exists():
        import shutil
        shutil.rmtree(repo)
    _restic(repo, password, "init")
    _restic(repo, password, "backup", "--host", "demo", "--tag", "demo", ".", cwd=app_dir)
    src = s.scalar(select(BackupSource).where(BackupSource.name == SOURCE_NAME))
    if src is None:
        src = BackupSource(project_id=default_project(s).id, name=SOURCE_NAME, adapter="restic",
                           config_json={"repository": str(repo)}, secret_ref=store_secret(s, {"password": password}))
        s.add(src)
    else:
        src.config_json = {"repository": str(repo)}
        src.secret_ref = store_secret(s, {"password": password}, src.secret_ref)
    s.flush()
    sha = definition_sha256(DEFINITION)
    app = ProtectedApp(project_id=src.project_id, source_id=src.id, name=APP_NAME,
                       description="Demo app created by \"Try it with demo data\"", test_definition=DEFINITION,
                       definition_version=1, definition_sha256=sha)
    s.add(app)
    s.flush()
    s.add(TestDefinitionVersion(app_id=app.id, version=1, yaml=DEFINITION, sha256=sha, created_by=user.id if user else None))
    s.add(Policy(app_id=app.id))
    audit.record(s, "demo.created", actor=user, target_type="app", target_id=app.id)
    return {"app_id": app.id, "source_id": src.id, "created": True}


def break_demo(s: Session, user: User | None) -> dict:
    """Simulate a bad backup: two notes lost and the database truncated, then take a new snapshot."""
    from restoreproof.security.crypto import load_secret
    src = s.scalar(select(BackupSource).where(BackupSource.name == SOURCE_NAME))
    if src is None:
        raise DemoError("create the demo first")
    _, app_dir, repo = _paths()
    for n in (4, 5):
        (app_dir / "notes" / f"note-{n}.md").unlink(missing_ok=True)
    db = app_dir / "notes.db"
    if db.exists():
        data = db.read_bytes()
        db.write_bytes(data[: max(100, len(data) // 3)])
    _restic(repo, load_secret(s, src.secret_ref)["password"], "backup", "--host", "demo", "--tag", "demo", ".", cwd=app_dir)
    audit.record(s, "demo.broken", actor=user)
    return {"broken": True, "what": ["notes 4 and 5 deleted", "notes.db truncated (a torn copy)"]}


def repair_demo(s: Session, user: User | None) -> dict:
    from restoreproof.security.crypto import load_secret
    src = s.scalar(select(BackupSource).where(BackupSource.name == SOURCE_NAME))
    if src is None:
        raise DemoError("create the demo first")
    _, app_dir, repo = _paths()
    _make_app_files(app_dir)
    _restic(repo, load_secret(s, src.secret_ref)["password"], "backup", "--host", "demo", "--tag", "demo", ".", cwd=app_dir)
    return {"repaired": True}

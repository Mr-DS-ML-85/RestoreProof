"""Templates, SQLite checks, trusted baselines, remediation hints, readiness report, retention."""

from __future__ import annotations

import gzip
import shutil
import sqlite3
from datetime import timedelta

import pytest
from sqlalchemy import select

from tests.conftest import HAS_DOCKER, REPO_PASSWORD, restic
from tests.helpers import client, make_app, make_source, run_test

pytestmark = pytest.mark.integration


def _checks(c, h, job_id):
    return {x["name"]: x for x in c.get(f"/api/v1/jobs/{job_id}/checks", headers=h).json()}


def _vaultwarden_tree(root):
    root.mkdir(parents=True)
    db = sqlite3.connect(root / "db.sqlite3")
    db.executescript("""
        CREATE TABLE users (uuid TEXT PRIMARY KEY, email TEXT);
        CREATE TABLE ciphers (uuid TEXT PRIMARY KEY, data TEXT);
        CREATE TABLE organizations (uuid TEXT PRIMARY KEY);
        CREATE TABLE devices (uuid TEXT PRIMARY KEY);
        INSERT INTO users VALUES ('u1', 'a@example.test');
        INSERT INTO ciphers VALUES ('c1', 'x'), ('c2', 'y');
    """)
    db.commit()
    db.close()
    (root / "rsa_key.pem").write_text("-----BEGIN PRIVATE KEY-----\nMIIfake\n-----END PRIVATE KEY-----\n")
    (root / "attachments").mkdir()
    for i in range(20):
        (root / "attachments" / f"file{i}.bin").write_bytes(bytes([i]) * 100)


def _template_app(c, h, sid, template, answers):
    r = c.post(f"/api/v1/templates/{template}/render", headers=h, json={"answers": answers})
    assert r.status_code == 200, r.text
    return make_app(c, h, sid, r.json()["test_definition"])


def test_templates_list_and_render_validation(env):
    c, h = client()
    ts = c.get("/api/v1/templates", headers=h).json()
    assert {"vaultwarden", "home-assistant", "paperless-ngx", "nextcloud", "immich", "gitea"} <= {t["id"] for t in ts}
    bad = c.post("/api/v1/templates/generic-files/render", headers=h,
                 json={"answers": {"name": "x", "required_files": "../../etc/passwd"}})
    assert bad.status_code == 422 and "traversal" in bad.text
    inj = c.post("/api/v1/templates/generic-files/render", headers=h,
                 json={"answers": {"name": "x\nspec: {evil: 1}", "base_path": "a: {b: c}"}})
    # YAML structure cannot be injected through answers; worst case the value is rejected by the schema.
    assert inj.status_code in (200, 422)
    if inj.status_code == 200:
        import yaml
        doc = yaml.safe_load(inj.json()["test_definition"])
        assert "evil" not in doc["spec"] and set(doc["metadata"]) == {"name", "description"}


def test_vaultwarden_template_sqlite_checks_pass_then_detect_corruption(env, tmp_path):
    repo = tmp_path / "repo"
    restic(repo, "init")
    vw = tmp_path / "vw"
    _vaultwarden_tree(vw)
    restic(repo, "backup", ".", cwd=vw)
    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    aid = _template_app(c, h, sid, "vaultwarden", {"name": "vault", "start_app": False})
    job = run_test(c, h, aid)
    ch = _checks(c, h, job["id"])
    assert job["status"] == "passed", {k: (v["status"], v["message"]) for k, v in ch.items()}
    assert ch["sqlite_integrity:db.sqlite3"]["status"] == "passed"
    assert ch["has-users"]["details"]["actual"] == 1
    assert ch["inventory"]["status"] == "skipped" and ch["inventory"]["required"] is False

    # A torn copy of the database: overwrite the middle of the file.
    raw = bytearray((vw / "db.sqlite3").read_bytes())
    raw[len(raw) // 2: len(raw) // 2 + 2048] = b"\xff" * 2048
    (vw / "db.sqlite3").write_bytes(bytes(raw))
    restic(repo, "backup", ".", cwd=vw)
    job = run_test(c, h, aid)
    ch = _checks(c, h, job["id"])
    assert job["status"] == "failed"
    assert ch["sqlite_integrity:db.sqlite3"]["status"] == "failed"
    assert "hint" in ch["sqlite_integrity:db.sqlite3"]["details"]
    assert "sqlite3" in ch["sqlite_integrity:db.sqlite3"]["details"]["hint"]


def test_sqlite_query_cannot_write(env, tmp_path):
    from restoreproof.checks.sqlite import run_sqlite_check
    from restoreproof.definitions import SqliteQuery

    _vaultwarden_tree(tmp_path / "d")
    q = SqliteQuery(type="sqlite_query", path="db.sqlite3",
                    query="WITH x AS (SELECT 1) SELECT count(*) FROM users", expect=1)
    assert run_sqlite_check(q, tmp_path / "d", tmp_path)[0] == "passed"
    # The schema blocks non-SELECT text; the authorizer blocks anything that slips through.
    sneaky = SqliteQuery.model_construct(type="sqlite_query", path="db.sqlite3", query="DELETE FROM users",
                                         expect=0, op="eq", name=None, required=True)
    status, msg, _ = run_sqlite_check(sneaky, tmp_path / "d", tmp_path)
    assert status == "failed" and ("not authorized" in msg or "readonly" in msg)
    assert sqlite3.connect(tmp_path / "d" / "db.sqlite3").execute("SELECT count(*) FROM users").fetchone()[0] == 1


def test_sqlite_wal_is_applied_on_a_copy(env, tmp_path):
    from restoreproof.checks.sqlite import run_sqlite_check
    from restoreproof.definitions import SqliteQuery

    d = tmp_path / "wal"
    d.mkdir()
    keep = sqlite3.connect(d / "app.db")
    keep.execute("PRAGMA journal_mode=WAL")
    keep.execute("PRAGMA wal_autocheckpoint=0")
    keep.execute("CREATE TABLE t (x)")
    keep.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(50)])
    keep.commit()
    # Simulate a file-level backup taken while the app is running: copy db + wal without checkpointing.
    snap = tmp_path / "snap"
    snap.mkdir()
    shutil.copy(d / "app.db", snap / "app.db")
    shutil.copy(d / "app.db-wal", snap / "app.db-wal")
    keep.close()
    before = (snap / "app.db").read_bytes()
    q = SqliteQuery(type="sqlite_query", path="app.db", query="SELECT count(*) FROM t", expect=50)
    status, _, details = run_sqlite_check(q, snap, tmp_path / "scratch")
    assert status == "passed" and details["wal_applied"]
    assert (snap / "app.db").read_bytes() == before  # restored copy untouched


def test_baseline_detects_silently_shrinking_backup(env, tmp_path):
    repo = tmp_path / "repo"
    restic(repo, "init")
    src = tmp_path / "docs"
    (src / "originals").mkdir(parents=True)
    for i in range(40):
        (src / "originals" / f"doc{i:03}.pdf").write_bytes(b"%PDF" + bytes([i]) * 500)
    restic(repo, "backup", ".", cwd=src)
    c, h = client()
    aid = _template_app(c, h, make_source(c, h, repo, REPO_PASSWORD), "generic-files",
                        {"name": "docs", "required_dirs": "originals"})
    first = run_test(c, h, aid)
    assert first["status"] == "passed"
    r = c.post(f"/api/v1/apps/{aid}/baselines", headers=h, json={"job_id": first["id"]})
    assert r.status_code == 201, r.text
    assert r.json()[0]["file_count"] == 40

    # Normal churn: 1 file changed, 1 added -> still passes.
    (src / "originals" / "doc000.pdf").write_bytes(b"%PDF changed")
    (src / "originals" / "new.pdf").write_bytes(b"%PDF new")
    restic(repo, "backup", ".", cwd=src)
    ok = run_test(c, h, aid)
    inv = _checks(c, h, ok["id"])["inventory"]
    assert ok["status"] == "passed" and inv["details"]["changed"] == 1 and inv["details"]["added"] == 1

    # A misconfigured backup now only captures part of the folder: 15 of 40 files are gone.
    for i in range(25, 40):
        (src / "originals" / f"doc{i:03}.pdf").unlink()
    restic(repo, "backup", ".", cwd=src)
    bad = run_test(c, h, aid)
    inv = _checks(c, h, bad["id"])["inventory"]
    assert bad["status"] == "failed"
    assert inv["details"]["missing"] == 15 and "baseline files are missing" in inv["message"]
    assert "approve a new baseline" in inv["details"]["hint"]


def test_wrong_base_path_gets_a_suggestion(env, tmp_path):
    repo = tmp_path / "repo"
    restic(repo, "init")
    src = tmp_path / "srv" / "app"
    (src / "data").mkdir(parents=True)
    (src / "data" / "important.json").write_text("{}")
    restic(repo, "backup", str(src))  # absolute path backup -> restores under tmp/.../srv/app
    c, h = client()
    aid = _template_app(c, h, make_source(c, h, repo, REPO_PASSWORD), "generic-files",
                        {"name": "app", "base_path": "srv/app", "required_files": "data/important.json"})
    job = run_test(c, h, aid)
    ch = _checks(c, h, job["id"])
    assert job["status"] == "failed"
    suggested = ch["restore_base_present"]["details"]["suggested_base_paths"]
    assert suggested and suggested[0].endswith("srv/app")
    assert "Try basePath" in ch["restore_base_present"]["message"]


def test_missing_file_suggests_where_it_actually_is(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    aid = _template_app(c, h, make_source(c, h, repo, REPO_PASSWORD), "generic-files",
                        {"name": "moved", "required_files": "important.json", "inventory": False})
    job = run_test(c, h, aid)
    ch = _checks(c, h, job["id"])["file_exists:important.json"]
    assert ch["status"] == "failed"
    assert ch["details"]["suggestions"] == ["data/important.json"]


def test_job_level_hint_and_readiness_report(env, tmp_path, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    good = _template_app(c, h, make_source(c, h, repo, REPO_PASSWORD), "generic-files",
                         {"name": "good", "required_files": "data/notes.txt"})
    bad = _template_app(c, h, make_source(c, h, repo, "nope-wrong", name="wrong"), "generic-files",
                        {"name": "bad", "required_files": "data/notes.txt"})
    _template_app(c, h, make_source(c, h, repo, REPO_PASSWORD, name="r3"), "generic-files", {"name": "never"})
    assert run_test(c, h, good)["status"] == "passed"
    b = run_test(c, h, bad)
    assert b["summary"]["hint"].startswith("The repository rejected the password")
    rep = c.get("/api/v1/readiness-report", headers=h).json()
    verdicts = {a["name"]: a["verdict"] for a in rep["applications"]}
    assert verdicts == {"good": "ready", "bad": "not_ready", "never": "untested"}
    from restoreproof.evidence.manifest import verify
    assert verify(rep)["hash_ok"]
    html = c.get("/api/v1/readiness-report?format=html", headers=h)
    assert html.status_code == 200 and "Recovery Readiness Report" in html.text and "not guarantee" not in ""


def test_retention_purges_old_files_but_keeps_latest_pass_and_rows(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    aid = _template_app(c, h, make_source(c, h, repo, REPO_PASSWORD), "generic-files",
                        {"name": "ret", "required_files": "data/notes.txt"})
    j1 = run_test(c, h, aid)
    j2 = run_test(c, h, aid)
    assert j1["status"] == j2["status"] == "passed"
    from restoreproof.db.models import EvidenceArtifact, JobAttempt, utcnow
    from restoreproof.db.session import session_scope
    from restoreproof.evidence.retention import purge
    assert c.put("/api/v1/settings/retention", headers=h,
                 json={"log_days": 1, "report_days": 1, "inventory_days": 1}).status_code == 200
    removed = purge(utcnow() + timedelta(days=3))
    with session_scope() as s:
        a1 = s.scalar(select(JobAttempt.id).where(JobAttempt.job_id == j1["id"]))
        a2 = s.scalar(select(JobAttempt.id).where(JobAttempt.job_id == j2["id"]))
        old = s.scalars(select(EvidenceArtifact).where(EvidenceArtifact.attempt_id == a1)).all()
        latest = s.scalars(select(EvidenceArtifact).where(EvidenceArtifact.attempt_id == a2)).all()
        assert old and all(x.purged_at for x in old)
        assert latest and not any(x.purged_at for x in latest)
    assert removed["files"] == len(old)
    # Old run still shows its result; report file is gone with a clear status.
    assert c.get(f"/api/v1/jobs/{j1['id']}", headers=h).json()["status"] == "passed"
    assert c.get(f"/api/v1/jobs/{j1['id']}/report", headers=h).status_code in (404, 410)
    assert c.get(f"/api/v1/jobs/{j2['id']}/report", headers=h).status_code == 200


@pytest.mark.docker
@pytest.mark.skipif(not HAS_DOCKER, reason="docker daemon not available")
# Debian-based images use dash as /bin/sh (no `pipefail`): this regressed once with Immich's Postgres image.
@pytest.mark.parametrize("image", ["postgres:16-alpine", "postgres:16-bookworm"])
def test_gzip_postgres_dump(env, tmp_path, image):
    repo = tmp_path / "repo"
    restic(repo, "init")
    src = tmp_path / "pg"
    (src / "db").mkdir(parents=True)
    with gzip.open(src / "db" / "dump.sql.gz", "wt") as fh:
        fh.write("CREATE TABLE public.users (id int); INSERT INTO public.users VALUES (1),(2);\n")
    restic(repo, "backup", ".", cwd=src)
    c, h = client()
    r = c.post("/api/v1/templates/postgres-app/render", headers=h, json={"answers": {
        "name": "gz", "dump_path": "db/dump.sql.gz", "tables": "public.users", "nonempty_table": "public.users",
        "inventory": False}})
    defn = r.json()["test_definition"].replace("      version: '16'\n", f"      version: '16'\n      image: {image}\n")
    assert f"image: {image}" in defn
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn)
    job = run_test(c, h, aid)
    ch = _checks(c, h, job["id"])
    assert job["status"] == "passed", {k: (v["status"], v["message"]) for k, v in ch.items()}
    assert ch["postgres_row_count:db"]["details"]["actual"] == 2


def test_failure_notification_says_what_to_do_and_leaks_nothing(env, restic_repo):
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    received = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            received.append((dict(self.headers), _json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    repo, src, _ = restic_repo
    c, h = client()
    r = c.post("/api/v1/notifications", headers=h, json={
        "name": "hook", "type": "webhook", "events": ["recovery_failed"],
        "secret": {"url": f"http://127.0.0.1:{srv.server_port}/hook", "bearer_token": "hook-token-123456"}})
    assert r.status_code == 201
    assert "hook-token" not in r.text and "127.0.0.1" not in r.text  # secret stays write-only
    aid = _template_app(c, h, make_source(c, h, repo, REPO_PASSWORD), "generic-files",
                        {"name": "notify", "required_files": "data/does-not-exist.txt", "inventory": False})
    job = run_test(c, h, aid)
    srv.shutdown()
    assert job["status"] == "failed"
    assert len(received) == 1
    headers, body = received[0]
    assert headers["Authorization"] == "Bearer hook-token-123456"
    assert body["event"] == "recovery_failed" and body["application"] == "notify"
    assert "does-not-exist" in body["message"] and body["next_step"]
    assert body["report_url"].endswith(f"/#/jobs/{job['id']}")
    assert REPO_PASSWORD not in _json.dumps(body)


def test_worker_offline_alert_only_when_no_worker_runs(env, monkeypatch):
    from restoreproof.db.models import WorkerRecord, utcnow
    from restoreproof.db.session import session_scope
    from restoreproof.scheduler import scheduler

    sent = []
    monkeypatch.setattr(scheduler, "notify", lambda ev, payload: sent.append(ev))
    with session_scope() as s:
        s.get(WorkerRecord, "test-worker").heartbeat_at = utcnow()
        s.add(WorkerRecord(id="old-container", hostname="x", version="0.1.0",
                           heartbeat_at=utcnow() - timedelta(hours=2)))
    scheduler._check_workers(utcnow())
    assert sent == []  # replaced by a restart: not an outage
    with session_scope() as s:
        s.get(WorkerRecord, "test-worker").heartbeat_at = utcnow() - timedelta(hours=1)
        s.get(WorkerRecord, "old-container").offline_notified = False
    scheduler._check_workers(utcnow())
    scheduler._check_workers(utcnow())
    assert sent == ["worker_offline"]  # exactly one alert while nothing is running

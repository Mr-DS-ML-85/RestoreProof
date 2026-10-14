"""Backup module against real servers for every protocol, plus space-guard fallback and consistency hooks.

Each protocol test: create destination -> back up real files -> run a recovery test that restores from that
same destination and verifies the files. Google Drive needs a real OAuth token and is covered by a config test.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import subprocess
import time
from pathlib import Path

import pytest

from tests.conftest import HAS_DOCKER, HAS_RESTIC
from tests.helpers import client, make_app

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAS_RESTIC, reason="restic not installed")]
RCLONE = Path(__file__).resolve().parents[2] / ".tools" / "rclone"
needs_rclone = pytest.mark.skipif(not RCLONE.exists() and not shutil.which("rclone"),
                                  reason="rclone binary not available (.tools/rclone)")
needs_docker = pytest.mark.skipif(not HAS_DOCKER, reason="docker not available")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.5)
    raise AssertionError(f"port {port} never opened")


@pytest.fixture
def rclone_env(env, monkeypatch):
    from restoreproof.db.session import reset_caches
    binary = str(RCLONE) if RCLONE.exists() else shutil.which("rclone")
    monkeypatch.setenv("RESTOREPROOF_RCLONE_BINARY", binary)
    reset_caches()
    from restoreproof.config import get_settings
    return binary, get_settings()


@pytest.fixture
def data(tmp_path):
    d = tmp_path / "app-data"
    (d / "docs").mkdir(parents=True)
    for i in range(5):
        (d / "docs" / f"file{i}.txt").write_text(f"document {i}\n" * 50)
    (d / "settings.json").write_text(json.dumps({"ok": True}))
    return d


def _flow(c, h, name, location, secret, data: Path, *, password=None):
    body = {"name": name, "location": location, "secret": secret}
    if password:
        body["repository_password"] = password
    r = c.post("/api/v1/destinations", headers=h, json=body)
    assert r.status_code == 201, r.text
    dest = r.json()
    chk = c.post(f"/api/v1/destinations/{dest['id']}/check", headers=h).json()
    assert chk["ok"], chk
    r = c.post("/api/v1/backup-plans", headers=h, json={
        "name": f"{name}-plan", "paths": [str(data)], "destination_ids": [dest["id"]]})
    assert r.status_code == 201, r.text
    plan = r.json()
    run = _run_plan(c, h, plan["id"])
    assert run["status"] == "succeeded", run
    assert run["snapshot_id"] and run["files_new"] >= 6
    # The destination is immediately usable by recovery tests.
    defn = c.post("/api/v1/templates/generic-files/render", headers=h, json={"answers": {
        "name": f"{name}-verify", "base_path": str(data).lstrip("/"), "required_files": "settings.json",
        "json_files": "settings.json", "min_files": 6, "inventory": False}}).json()["test_definition"]
    aid = make_app(c, h, dest["id"], defn)
    from tests.helpers import run_test
    job = run_test(c, h, aid)
    assert job["status"] == "passed", c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).text
    return dest, plan, run


def _run_plan(c, h, plan_id):
    from restoreproof.jobs import worker
    r = c.post(f"/api/v1/backup-plans/{plan_id}/run", headers=h)
    assert r.status_code == 202, r.text
    worker.run_once()
    return c.get(f"/api/v1/backup-runs/{r.json()['id']}", headers=h).json()


# -- protocols -------------------------------------------------------------------------------------------
def test_local_destination_and_generated_password(env, data, tmp_path):
    c, h = client()
    r = c.post("/api/v1/destinations", headers=h, json={"name": "usb", "location": {"type": "local",
                                                                                    "path": str(tmp_path / "usb-repo")}})
    assert "repository_password" in r.json() and "only way to decrypt" in r.json()["repository_password_note"]
    assert "repository_password" not in c.get("/api/v1/destinations", headers=h).text
    dest, plan, run = _flow(c, h, "local", {"type": "local", "path": str(tmp_path / "local-repo")}, {}, data)
    assert run["decision"][-1]["verdict"] == "chosen" and "free" in run["decision"][-1]["reason"]


@needs_docker
def test_sftp_linux_server_with_pinned_host_key(env, data, tmp_path):
    key = tmp_path / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    port = free_port()
    name = f"rp-sftp-{port}"
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:22",
                    "-v", f"{key}.pub:/home/rp/.ssh/keys/id.pub:ro", "atmoz/sftp:alpine", "rp::1001::upload"],
                   check=True, capture_output=True)
    try:
        wait_port(port)
        c, h = client()
        for _ in range(30):  # the container generates its host keys on first start
            r = c.post("/api/v1/destinations/scan-host-key", headers=h, json={"host": "127.0.0.1", "port": port})
            if r.status_code == 200:
                break
            time.sleep(1)
        assert r.status_code == 200, r.text
        scanned = r.json()["keys"][0]
        assert scanned["key"].startswith("ssh-ed25519 ") and scanned["fingerprint"].startswith("SHA256:")
        loc = {"type": "sftp", "host": "127.0.0.1", "port": port, "user": "rp", "path": "/upload/repo",
               "host_key": scanned["key"]}
        _flow(c, h, "sftp", loc, {"private_key": key.read_text()}, data)
        # A different host key (man-in-the-middle) must be refused.
        bad = c.post("/api/v1/destinations", headers=h, json={"name": "sftp-mitm", "location": {
            **loc, "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
            "secret": {"private_key": key.read_text()}}).json()
        chk = c.post(f"/api/v1/destinations/{bad['id']}/check", headers=h).json()
        assert chk["ok"] is False
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@needs_docker
def test_rest_server(env, data):
    port = free_port()
    name = f"rp-rest-{port}"
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:8000",
                    "-e", "DISABLE_AUTHENTICATION=1", "restic/rest-server:0.14.0"], check=True, capture_output=True)
    try:
        wait_port(port)
        c, h = client()
        _flow(c, h, "rest", {"type": "rest", "url": f"http://127.0.0.1:{port}/rp"}, {}, data)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@needs_docker
@needs_rclone
def test_smb_share(rclone_env, data):
    port = free_port()
    name = f"rp-smb-{port}"
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:445",
                    "dperson/samba:latest", "-p", "-u", "rp;smb-test-pass", "-s", "backups;/share;yes;no;no;rp"],
                   check=True, capture_output=True)
    try:
        wait_port(port)
        time.sleep(3)
        c, h = client()
        _flow(c, h, "smb", {"type": "smb", "host": "127.0.0.1", "port": port, "share": "backups",
                            "path": "restoreproof", "user": "rp"}, {"password": "smb-test-pass"}, data)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@needs_rclone
@pytest.mark.parametrize("proto", ["webdav", "ftp"])
def test_webdav_and_ftp(rclone_env, data, tmp_path, proto):
    binary, _ = rclone_env
    root = tmp_path / f"{proto}-root"
    root.mkdir()
    port = free_port()
    srv = subprocess.Popen([binary, "serve", proto, str(root), "--addr", f"127.0.0.1:{port}", "--user", "rp",
                            "--pass", f"{proto}-test-pass"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_port(port)
        c, h = client()
        loc = ({"type": "webdav", "url": f"http://127.0.0.1:{port}", "vendor": "other", "user": "rp",
                "path": "restoreproof"} if proto == "webdav" else
               {"type": "ftp", "host": "127.0.0.1", "port": port, "user": "rp", "path": "restoreproof", "tls": "none"})
        _flow(c, h, proto, loc, {"password": f"{proto}-test-pass"}, data)
        assert (root / "restoreproof" / "config").exists()  # repository really lives on that server
    finally:
        srv.terminate()


@needs_rclone
def test_s3_compatible(rclone_env, data, tmp_path):
    binary, _ = rclone_env
    root = tmp_path / "s3-root"
    (root / "rp-bucket").mkdir(parents=True)
    port = free_port()
    srv = subprocess.Popen([binary, "serve", "s3", str(root), "--addr", f"127.0.0.1:{port}",
                            "--auth-key", "RPACCESSKEY,rp-s3-secret-key"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_port(port)
        c, h = client()
        _flow(c, h, "s3", {"type": "s3", "endpoint": f"http://127.0.0.1:{port}", "bucket": "rp-bucket",
                           "prefix": "restic", "region": "us-east-1"},
              {"access_key": "RPACCESSKEY", "secret_key": "rp-s3-secret-key"}, data)
    finally:
        srv.terminate()


def test_google_drive_configuration_is_translated_without_secrets_in_argv(tmp_path):
    from restoreproof.backups import locations
    loc = locations.parse({"type": "gdrive", "path": "backups/homelab", "root_folder_id": "abc123"})
    token = json.dumps({"access_token": "ya29.x", "refresh_token": "1//r", "expiry": "2026-01-01T00:00:00Z"})
    res = locations.resolve(loc, {"token": token}, tmp_path)
    assert res.repository == "rclone:RPDEST:backups/homelab"
    assert res.env["RCLONE_CONFIG_RPDEST_TYPE"] == "drive" and res.env["RCLONE_CONFIG_RPDEST_TOKEN"] == token
    assert not any(token in o for o in res.options)
    with pytest.raises(ValueError):
        locations.resolve(loc, {"token": "not-a-token"}, tmp_path)


# -- safety & behaviour ----------------------------------------------------------------------------------
def test_space_guard_falls_back_to_next_destination(env, data, tmp_path, monkeypatch):
    from restoreproof.backups import engine
    c, h = client()
    (tmp_path / "small").mkdir()  # the (nearly full) disk is mounted here; the repo folder does not exist yet
    small = c.post("/api/v1/destinations", headers=h, json={"name": "small-disk", "location": {
        "type": "local", "path": str(tmp_path / "small" / "repo")}}).json()
    nas = c.post("/api/v1/destinations", headers=h, json={"name": "nas", "location": {
        "type": "local", "path": str(tmp_path / "nas" / "repo")}}).json()
    plan = c.post("/api/v1/backup-plans", headers=h, json={"name": "fallback", "paths": [str(data)],
                                                          "destination_ids": [small["id"], nas["id"]]}).json()
    real = shutil.disk_usage

    def fake(path):
        u = real(path)
        if "small" in str(path):
            return type(u)(total=1000 * 1024**3, used=999 * 1024**3, free=1 * 1024**3)  # 1 GB free of 1 TB
        return u
    monkeypatch.setattr(engine.shutil, "disk_usage", fake)
    run = _run_plan(c, h, plan["id"])
    assert run["status"] == "succeeded", run
    assert run["destination_id"] == nas["id"]
    v = {d["destination"]: d for d in run["decision"] if "destination" in d}
    assert v["small-disk"]["verdict"] == "skipped" and "not enough space" in v["small-disk"]["reason"]
    assert v["nas"]["verdict"] == "chosen"
    assert not (tmp_path / "small" / "repo").exists()  # nothing was written to the full disk


def test_no_destination_fits_blocks_and_writes_nothing(env, data, tmp_path, monkeypatch):
    from restoreproof.backups import engine
    c, h = client()
    d = c.post("/api/v1/destinations", headers=h, json={"name": "full", "location": {
        "type": "local", "path": str(tmp_path / "full" / "repo")}}).json()
    plan = c.post("/api/v1/backup-plans", headers=h, json={"name": "nowhere", "paths": [str(data)],
                                                          "destination_ids": [d["id"]]}).json()
    real = shutil.disk_usage
    monkeypatch.setattr(engine.shutil, "disk_usage", lambda p: type(real(p))(total=10**12, used=10**12 - 10**6, free=10**6))
    run = _run_plan(c, h, plan["id"])
    assert run["status"] == "blocked" and run["error_code"] == "no_destination"
    assert "not enough space" in run["error_message"]


def test_unreadable_file_makes_backup_partial_not_success(env, data, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    secret_file = data / "docs" / "locked.txt"
    secret_file.write_text("x")
    secret_file.chmod(0)
    try:
        c, h = client()
        d = c.post("/api/v1/destinations", headers=h, json={"name": "p", "location": {
            "type": "local", "path": str(tmp_path / "p-repo")}}).json()
        plan = c.post("/api/v1/backup-plans", headers=h, json={"name": "partial", "paths": [str(data)],
                                                              "destination_ids": [d["id"]]}).json()
        run = _run_plan(c, h, plan["id"])
        assert run["status"] == "partial" and run["error_code"] == "unreadable_files"
        assert "locked.txt" in run["error_message"]
    finally:
        secret_file.chmod(0o600)


def test_sqlite_hook_makes_live_database_consistent(env, tmp_path):
    app = tmp_path / "vault"
    app.mkdir()
    live = sqlite3.connect(app / "db.sqlite3")
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("PRAGMA wal_autocheckpoint=0")
    live.execute("CREATE TABLE items (x)")
    live.executemany("INSERT INTO items VALUES (?)", [(i,) for i in range(500)])
    live.commit()  # data only in the WAL; the main file alone is incomplete
    c, h = client()
    d = c.post("/api/v1/destinations", headers=h, json={"name": "hook-dest", "location": {
        "type": "local", "path": str(tmp_path / "hook-repo")}}).json()
    plan = c.post("/api/v1/backup-plans", headers=h, json={
        "name": "vault", "paths": [str(app)], "destination_ids": [d["id"]], "excludes": ["db.sqlite3-*"],
        "hooks": [{"type": "sqlite_backup", "source": str(app / "db.sqlite3"),
                   "output": str(app / "backup" / "db.sqlite3")}]})
    assert plan.status_code == 201, plan.text
    run = _run_plan(c, h, plan.json()["id"])
    live.close()
    assert run["status"] == "succeeded", run
    defn = c.post("/api/v1/templates/generic-files/render", headers=h, json={"answers": {
        "name": "vault-verify", "base_path": str(app).lstrip("/"), "required_files": "backup/db.sqlite3",
        "inventory": False}}).json()["test_definition"]
    defn = defn.replace("  checks:\n", "  checks:\n  - {type: sqlite_query, path: backup/db.sqlite3, "
                                        "query: 'SELECT count(*) FROM items', expect: 500}\n")
    from tests.helpers import run_test
    job = run_test(c, h, make_app(c, h, d["id"], defn))
    checks = {x["name"]: x for x in c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).json()}
    assert job["status"] == "passed", checks
    assert checks["sqlite_query:backup/db.sqlite3"]["details"]["actual"] == 500


def test_hook_output_must_be_inside_backed_up_paths(env, tmp_path):
    c, h = client()
    d = c.post("/api/v1/destinations", headers=h, json={"name": "x", "location": {"type": "local",
                                                                                  "path": str(tmp_path / "r")}}).json()
    r = c.post("/api/v1/backup-plans", headers=h, json={"name": "bad", "paths": [str(tmp_path / "a")],
                                                       "destination_ids": [d["id"]],
                                                       "hooks": [{"type": "sqlite_backup", "source": "/x/db",
                                                                  "output": "/elsewhere/db"}]})
    assert r.status_code == 422 and "would not be backed up" in r.text
    r = c.post("/api/v1/backup-plans", headers=h, json={"name": "shell", "paths": [str(tmp_path)],
                                                       "destination_ids": [d["id"]],
                                                       "hooks": [{"type": "shell", "command": "rm -rf /"}]})
    assert r.status_code == 422


def test_failed_postgres_dump_keeps_previous_dump(env, tmp_path):
    from restoreproof.backups import hooks as hk
    out = tmp_path / "db" / "dump.sql"
    out.parent.mkdir()
    out.write_text("previous good dump")
    with pytest.raises(hk.HookError):
        hk.run_postgres_dump(hk.parse([{"type": "postgres_dump", "container": "rp-no-such-container",
                                        "database": "app", "output": str(out)}])[0], timeout=30)
    assert out.read_text() == "previous good dump"


def test_backup_then_verify_queues_recovery_test(env, data, tmp_path):
    from restoreproof.jobs import worker
    c, h = client()
    d = c.post("/api/v1/destinations", headers=h, json={"name": "v", "location": {"type": "local",
                                                                                  "path": str(tmp_path / "v-repo")}}).json()
    c.post(f"/api/v1/destinations/{d['id']}/check", headers=h)
    defn = c.post("/api/v1/templates/generic-files/render", headers=h, json={"answers": {
        "name": "auto-verify", "base_path": str(data).lstrip("/"), "required_files": "settings.json",
        "inventory": False}}).json()["test_definition"]
    aid = make_app(c, h, d["id"], defn)
    plan = c.post("/api/v1/backup-plans", headers=h, json={"name": "verified", "paths": [str(data)],
                                                          "destination_ids": [d["id"]], "verify_app_ids": [aid]}).json()
    run = _run_plan(c, h, plan["id"])
    assert run["status"] == "succeeded" and len(run["verify_job_ids"]) == 1
    worker.run_once()  # the queued recovery test
    job = c.get(f"/api/v1/jobs/{run['verify_job_ids'][0]}", headers=h).json()
    assert job["status"] == "passed" and job["trigger"] == "after_backup"
    assert job["summary"]["recovery_point"] == run["snapshot_id"]


def test_secrets_never_leak_from_destinations(env, data, tmp_path):
    c, h = client()
    r = c.post("/api/v1/destinations", headers=h, json={"name": "ftp-x", "location": {
        "type": "ftp", "host": "127.0.0.1", "port": 2, "user": "u", "tls": "none"},
        "secret": {"password": "ftp-super-secret-99"}})
    assert r.status_code == 201
    for path in ("/api/v1/destinations", "/api/v1/sources", "/api/v1/audit-events"):
        assert "ftp-super-secret-99" not in c.get(path, headers=h).text
    bad = c.post("/api/v1/destinations", headers=h, json={"name": "bad", "location": {"type": "local", "path": "rel"}})
    assert bad.status_code == 422
    bad = c.post("/api/v1/destinations", headers=h, json={"name": "bad2", "location": {"type": "local", "path": "/x"},
                                                          "secret": {"evil": "1"}})
    assert bad.status_code == 422


def test_backup_writer_cannot_be_used_by_recovery_tests():
    from restoreproof.adapters.restic import ResticAdapter
    from restoreproof.backups.writer import ResticWriter
    assert not {"backup", "forget", "prune", "init"} & ResticAdapter.allowed_subcommands
    assert {"backup", "forget", "prune", "init"} <= ResticWriter.allowed_subcommands

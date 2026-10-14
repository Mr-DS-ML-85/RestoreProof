"""Home Assistant 2026.10.1: real first start and onboarding (owner user + core config, which creates the
default integrations), then the /config directory is backed up."""

from __future__ import annotations

import time

import httpx

from tests.realapps.conftest import backup, free_port, make_readable, run_template, summary, wait_http

IMAGE = "ghcr.io/home-assistant/home-assistant:2026.10.1"


def test_home_assistant_config_restores(env, tmp_path, containers):
    cfg = tmp_path / "ha-config"
    cfg.mkdir()
    port = free_port()
    containers.run("ha", "-v", f"{cfg}:/config", "-p", f"127.0.0.1:{port}:8123", IMAGE)
    base = f"http://127.0.0.1:{port}"
    wait_http(f"{base}/api/onboarding", timeout=600, ok=lambda r: r.status_code == 200)
    client_id = f"{base}/"
    r = httpx.post(f"{base}/api/onboarding/users", json={
        "client_id": client_id, "name": "Owner", "username": "owner", "password": "ha-test-pass-1", "language": "en"})
    assert r.status_code == 200, r.text
    tok = httpx.post(f"{base}/auth/token", data={"grant_type": "authorization_code", "code": r.json()["auth_code"],
                                                 "client_id": client_id}).json()["access_token"]
    hdr = {"authorization": f"Bearer {tok}"}
    r = httpx.post(f"{base}/api/onboarding/core_config", headers=hdr, json={}, timeout=60)
    assert r.status_code == 200, r.text
    # HA persists users and integrations with a delayed save; a real install has long since done so.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and not all(
            (cfg / ".storage" / f).exists() for f in ("auth", "core.config_entries")):
        time.sleep(2)
    containers.stop("ha")
    make_readable(cfg)
    repo = tmp_path / "repo"
    backup(repo, cfg)
    job, checks, _ = run_template("home-assistant", {"name": "home-assistant", "check_recorder": True}, repo)
    assert job["status"] == "passed", summary(checks)
    assert checks["user-accounts"]["status"] == "passed"
    assert checks["recorder-history"]["status"] == "passed", summary(checks)


def test_home_assistant_backup_without_hidden_storage_fails(env, tmp_path, containers):
    """Backing up /config with a tool that skips dot-folders loses every integration and user."""
    cfg = tmp_path / "ha-config"
    cfg.mkdir()
    port = free_port()
    containers.run("ha", "-v", f"{cfg}:/config", "-p", f"127.0.0.1:{port}:8123", IMAGE)
    wait_http(f"http://127.0.0.1:{port}/api/onboarding", timeout=600, ok=lambda r: r.status_code == 200)
    containers.stop("ha")
    make_readable(cfg)
    repo = tmp_path / "repo"
    backup(repo, cfg, "--exclude", ".storage")
    job, checks, _ = run_template("home-assistant", {"name": "home-assistant"}, repo)
    assert job["status"] == "failed", summary(checks)
    assert checks["dir_not_empty:.storage"]["status"] == "failed"
    assert checks["file_exists:configuration.yaml"]["status"] == "passed"

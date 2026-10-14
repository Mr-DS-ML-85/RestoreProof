"""Vaultwarden 1.37.4: real server creates a real database (user + vault items) and keys; the backup is taken
*while the server is running* (live SQLite with an un-checkpointed WAL); RestoreProof restores it and boots
the real Vaultwarden image on the restored data in isolation."""

from __future__ import annotations

import uuid

import httpx

from tests.realapps.conftest import backup, free_port, make_readable, run_template, summary, wait_http

IMAGE = "vaultwarden/server:1.37.4"


def _create_real_vault(base: str) -> int:
    tok = httpx.post(f"{base}/identity/accounts/register/send-verification-email",
                     json={"email": "owner@example.test", "name": "Owner", "receiveMarketingEmails": False}
                     ).text.strip().strip('"')  # returned as plain text when SMTP is not configured
    r = httpx.post(f"{base}/identity/accounts/register/finish", json={
        "email": "owner@example.test", "emailVerificationToken": tok, "masterPasswordHash": "dGVzdGhhc2g=",
        "masterPasswordHint": None, "userSymmetricKey": "2.AAAA|BBBB|CCCC",
        "userAsymmetricKeys": {"publicKey": "cHVi", "encryptedPrivateKey": "2.AAAA|BBBB|CCCC"},
        "kdf": 0, "kdfIterations": 600000})
    assert r.status_code == 200, r.text
    access = httpx.post(f"{base}/identity/connect/token", data={
        "grant_type": "password", "username": "owner@example.test", "password": "dGVzdGhhc2g=",
        "scope": "api offline_access", "client_id": "web", "deviceType": "9",
        "deviceIdentifier": str(uuid.uuid4()), "deviceName": "rp-test"}).json()["access_token"]
    hdr = {"authorization": f"Bearer {access}"}
    uid = httpx.get(f"{base}/api/accounts/profile", headers=hdr).json()["id"]
    for _ in range(3):
        r = httpx.post(f"{base}/api/ciphers", headers=hdr,
                       json={"type": 1, "name": "2.AAAA|BBBB|CCCC", "encryptedFor": uid, "login": {}})
        assert r.status_code == 200, r.text
    return 3


def test_vaultwarden_live_backup_restores_and_boots(env, tmp_path, containers):
    data = tmp_path / "vw-data"
    data.mkdir()
    port = free_port()
    containers.run("vw", "-e", "SIGNUPS_ALLOWED=true", "-v", f"{data}:/data", "-p", f"127.0.0.1:{port}:80", IMAGE)
    wait_http(f"http://127.0.0.1:{port}/alive", ok=lambda r: r.status_code == 200)
    items = _create_real_vault(f"http://127.0.0.1:{port}")
    make_readable(data)
    assert (data / "db.sqlite3-wal").stat().st_size > 0, "expected a live WAL to make this test meaningful"
    repo = tmp_path / "repo"
    backup(repo, data)  # taken while Vaultwarden is still running

    job, checks, _ = run_template("vaultwarden", {"name": "vaultwarden", "start_app": True, "image": IMAGE}, repo)
    assert job["status"] == "passed", summary(checks)
    assert checks["sqlite_integrity:db.sqlite3"]["details"]["wal_applied"] is True
    assert checks["has-users"]["details"]["actual"] == 1
    assert checks["has-vault-items"]["details"]["actual"] == items
    assert checks["service_ready:vaultwarden"]["status"] == "passed"
    assert checks["http:vaultwarden"]["status"] == "passed"
    assert checks["api-answers"]["status"] == "passed"
    assert job["summary"]["layers"] == {"recovery_point": "passed", "objectives": "passed", "data": "passed",
                                        "database": "passed", "application": "passed"}
    assert job["attempts"][-1]["cleanup_status"] == "completed"


def test_vaultwarden_backup_without_signing_key_fails(env, tmp_path, containers):
    """A common mistake: backing up only db.sqlite3. The vault restores but every session token breaks."""
    data = tmp_path / "vw-data"
    data.mkdir()
    port = free_port()
    containers.run("vw", "-e", "SIGNUPS_ALLOWED=true", "-v", f"{data}:/data", "-p", f"127.0.0.1:{port}:80", IMAGE)
    wait_http(f"http://127.0.0.1:{port}/alive", ok=lambda r: r.status_code == 200)
    _create_real_vault(f"http://127.0.0.1:{port}")
    containers.stop("vw")
    make_readable(data)
    (data / "rsa_key.pem").unlink()
    repo = tmp_path / "repo"
    backup(repo, data)
    job, checks, _ = run_template("vaultwarden", {"name": "vaultwarden", "start_app": False}, repo)
    assert job["status"] == "failed", summary(checks)
    assert checks["jwt-signing-key"]["status"] == "failed"
    assert checks["sqlite_integrity:db.sqlite3"]["status"] == "passed"

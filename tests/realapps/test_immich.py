"""Immich v3.3.1 with its real PostgreSQL (vectorchord) image: admin user, an uploaded photo, and the database
dump Immich itself writes to UPLOAD_LOCATION/backups. RestoreProof must import that dump into the same
Postgres image and find the user and the asset."""

from __future__ import annotations

import struct
import time
import zlib
from datetime import datetime, timezone

import httpx

from tests.realapps.conftest import backup, free_port, make_readable, run_template, summary, wait_http

SERVER = "ghcr.io/immich-app/immich-server:v3.3.1"
PG = "ghcr.io/immich-app/postgres:14-vectorchord0.4.3-pgvectors0.2.0"
VALKEY = "docker.io/valkey/valkey:9"


def _png(w: int = 8, h: int = 8, seed: int = 1) -> bytes:
    """A small valid RGB PNG; `seed` makes each image's content (and Immich checksum) unique."""
    rows = b"".join(b"\x00" + bytes(v for x in range(w) for v in ((x * seed) % 256, (y * 7) % 256, seed % 256))
                    for y in range(h))

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def _trigger_db_backup(api: str, hdr: dict) -> bool:
    """Ask Immich to run its own database backup job (endpoint names changed across versions)."""
    for method, path, body in (("POST", "/jobs", {"name": "DatabaseBackup"}),
                               ("POST", "/jobs", {"name": "database-backup"}),
                               ("PUT", "/jobs/backupDatabase", {"command": "start", "force": False}),
                               ("PUT", "/jobs/backup-database", {"command": "start", "force": False})):
        r = httpx.request(method, f"{api}{path}", headers=hdr, json=body, timeout=30)
        if r.status_code < 300:
            return True
    return False


def test_immich_dump_and_library_restore(env, tmp_path, containers):
    upload = tmp_path / "immich-upload"
    pgdata = tmp_path / "immich-pg"
    upload.mkdir()
    pgdata.mkdir()
    port = free_port()
    containers.run("database", "-e", "POSTGRES_PASSWORD=postgres", "-e", "POSTGRES_USER=postgres",
                   "-e", "POSTGRES_DB=immich", "-e", "POSTGRES_INITDB_ARGS=--data-checksums",
                   "--shm-size", "128m", "-v", f"{pgdata}:/var/lib/postgresql/data", PG)
    containers.run("redis", VALKEY)
    containers.run("server", "-e", "DB_HOSTNAME=database", "-e", "DB_USERNAME=postgres", "-e", "DB_PASSWORD=postgres",
                   "-e", "DB_DATABASE_NAME=immich", "-e", "REDIS_HOSTNAME=redis",
                   "-e", "IMMICH_MACHINE_LEARNING_ENABLED=false",
                   "-v", f"{upload}:/data", "-p", f"127.0.0.1:{port}:2283", SERVER)
    api = f"http://127.0.0.1:{port}/api"
    try:
        wait_http(f"{api}/server/ping", timeout=600, ok=lambda r: r.status_code == 200)
    except AssertionError:
        raise AssertionError(containers.logs("server")) from None

    r = httpx.post(f"{api}/auth/admin-sign-up", json={"email": "owner@example.test", "password": "immich-test-pw",
                                                      "name": "Owner"})
    assert r.status_code in (200, 201), r.text
    token = httpx.post(f"{api}/auth/login", json={"email": "owner@example.test",
                                                  "password": "immich-test-pw"}).json()["accessToken"]
    hdr = {"authorization": f"Bearer {token}"}
    now = datetime.now(timezone.utc).isoformat()
    for i in range(2):
        r = httpx.post(f"{api}/assets", headers=hdr, timeout=60,
                       files={"assetData": (f"photo{i}.png", _png(seed=i + 3), "image/png")},
                       data={"deviceAssetId": f"rp-test-{i}", "deviceId": "rp-test", "fileCreatedAt": now,
                             "fileModifiedAt": now})
        assert r.status_code in (200, 201), r.text

    backups = upload / "backups"
    used_builtin = _trigger_db_backup(api, hdr)
    deadline = time.monotonic() + 120
    while used_builtin and time.monotonic() < deadline and not list(backups.glob("immich-db-backup-*.sql.gz")):
        time.sleep(3)
    if not list(backups.glob("immich-db-backup-*.sql.gz")):
        # Fall back to the command from Immich's backup documentation, using Immich's file naming.
        dump = containers.exec("database", "sh", "-c",
                               "pg_dumpall --clean --if-exists --username=postgres | gzip | base64 -w0")
        import base64
        backups.mkdir(exist_ok=True)
        (backups / f"immich-db-backup-{datetime.now():%Y%m%dT%H%M%S}-v3.3.1-pg14.sql.gz").write_bytes(
            base64.b64decode(dump))
    containers.stop("server")
    make_readable(upload)
    repo = tmp_path / "repo"
    backup(repo, upload)

    job, checks, _ = run_template("immich", {"name": "immich", "pg_image": PG}, repo)  # template defaults
    info = f"builtin backup job used: {used_builtin}\n{summary(checks)}"
    assert job["status"] == "passed", info
    assert checks["has-users"]["details"]["actual"] == 1, info
    assert used_builtin, "Immich's own backup job should have produced the dump"
    assert checks["postgres_dump_present:db"]["details"]["file"].startswith("backups/immich-db-backup-"), info
    assert checks["has-assets"]["details"]["actual"] == 2, info

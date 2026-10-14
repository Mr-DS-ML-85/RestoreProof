"""Paperless-ngx 3.3.1 (SQLite + Redis): a real document consumed through the API, then data/ + media/
backed up together, as Paperless documents."""

from __future__ import annotations

import time

import httpx

from tests.realapps.conftest import backup, free_port, make_readable, run_template, summary, wait_http

IMAGE = "ghcr.io/paperless-ngx/paperless-ngx:3.3.1"
REDIS = "redis:7-alpine"
AUTH = ("admin", "paperless-test-pass")


def test_paperless_sqlite_documents_restore(env, tmp_path, containers):
    root = tmp_path / "paperless"
    for d in ("data", "media", "consume"):
        (root / d).mkdir(parents=True)
    port = free_port()
    containers.run("redis", REDIS)
    containers.run("app", "-e", "PAPERLESS_REDIS=redis://redis:6379", "-e", "PAPERLESS_ADMIN_USER=admin",
                   "-e", "PAPERLESS_ADMIN_PASSWORD=paperless-test-pass", "-e", "USERMAP_UID=1000",
                   "-e", "PAPERLESS_SECRET_KEY=rp-test-secret-key-0123456789abcdef0123456789",
                   "-e", "USERMAP_GID=1000", "-e", "PAPERLESS_OCR_LANGUAGE=eng",
                   "-v", f"{root / 'data'}:/usr/src/paperless/data", "-v", f"{root / 'media'}:/usr/src/paperless/media",
                   "-v", f"{root / 'consume'}:/usr/src/paperless/consume", "-p", f"127.0.0.1:{port}:8000", IMAGE)
    base = f"http://127.0.0.1:{port}"
    try:
        wait_http(f"{base}/api/documents/", timeout=600, ok=lambda r: r.status_code in (200, 401, 403))
    except AssertionError:
        raise AssertionError(containers.logs("app")) from None
    # The admin user is created shortly after the web server starts.
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and httpx.get(f"{base}/api/documents/", auth=AUTH).status_code != 200:
        time.sleep(3)
    for i in range(2):
        r = httpx.post(f"{base}/api/documents/post_document/", auth=AUTH, timeout=60,
                       files={"document": (f"invoice-{i}.txt", f"Invoice number {i}\nTotal 42 EUR\n".encode(),
                                           "text/plain")})
        assert r.status_code == 200, r.text
    deadline = time.monotonic() + 300
    count = 0
    while time.monotonic() < deadline:
        count = httpx.get(f"{base}/api/documents/", auth=AUTH).json().get("count", 0)
        if count >= 2:
            break
        time.sleep(3)
    assert count >= 2, containers.logs("app")
    containers.stop("app")
    make_readable(root)
    repo = tmp_path / "repo"
    backup(repo, root, "--exclude", "consume")
    job, checks, _ = run_template("paperless-ngx", {"name": "paperless", "db_engine": "sqlite"}, repo)
    assert job["status"] == "passed", summary(checks)
    assert checks["has-documents"]["details"]["actual"] == 2
    assert checks["dir_not_empty:media/documents/originals"]["status"] == "passed"

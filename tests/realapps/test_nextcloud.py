"""Nextcloud 35.0.1 + PostgreSQL 16: real auto-install, a real uploaded file, then the documented backup
procedure (maintenance mode on, pg_dump, back up files + dump together)."""

from __future__ import annotations

import httpx

from tests.realapps.conftest import backup, free_port, make_readable, run_template, summary, wait_http

IMAGE = "nextcloud:35.0.1-apache"
PG = "postgres:16-alpine"


def _real_nextcloud(containers, root, port):
    html = root / "html"
    html.mkdir(parents=True)
    containers.run("db", "-e", "POSTGRES_DB=nextcloud", "-e", "POSTGRES_USER=nextcloud",
                   "-e", "POSTGRES_PASSWORD=nc-db-pass", PG)
    containers.run("app", "-e", "POSTGRES_HOST=db", "-e", "POSTGRES_DB=nextcloud", "-e", "POSTGRES_USER=nextcloud",
                   "-e", "POSTGRES_PASSWORD=nc-db-pass", "-e", "NEXTCLOUD_ADMIN_USER=admin",
                   "-e", "NEXTCLOUD_ADMIN_PASSWORD=nc-admin-pass-1", "-e", "NEXTCLOUD_TRUSTED_DOMAINS=127.0.0.1",
                   "-v", f"{html}:/var/www/html", "-p", f"127.0.0.1:{port}:80", IMAGE)
    base = f"http://127.0.0.1:{port}"
    wait_http(f"{base}/status.php", timeout=600,
              ok=lambda r: r.status_code == 200 and r.json().get("installed") is True)
    r = httpx.put(f"{base}/remote.php/dav/files/admin/restore-me.txt", content=b"important family document",
                  auth=("admin", "nc-admin-pass-1"))
    assert r.status_code in (201, 204), r.text
    # Documented backup procedure: maintenance mode, dump, copy files.
    containers.exec("app", "su", "-s", "/bin/sh", "www-data", "-c", "php occ maintenance:mode --on")
    dump = containers.exec("db", "pg_dump", "-U", "nextcloud", "nextcloud")
    (root / "db").mkdir()
    (root / "db" / "nextcloud.sql").write_text(dump)
    roles = containers.exec("db", "psql", "-U", "nextcloud", "-d", "nextcloud", "-Atc",
                            "SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname='public'").split()
    return roles


def test_nextcloud_files_and_database_restore(env, tmp_path, containers):
    root = tmp_path / "nextcloud-backup"
    roles = _real_nextcloud(containers, root, free_port())
    containers.stop("app")
    make_readable(root)
    repo = tmp_path / "repo"
    backup(repo, root)
    job, checks, _ = run_template("nextcloud", {"name": "nextcloud", "app_dir": "html", "dump_path": "db/nextcloud.sql",
                                                "roles": ",".join(roles), "pg_version": "16"}, repo)
    assert job["status"] == "passed", f"owners={roles}\n{summary(checks)}"
    assert checks["postgres_row_count:db"]["details"]["actual"] >= 1


def test_nextcloud_without_database_dump_fails(env, tmp_path, containers):
    """Files-only backup (the most common Nextcloud mistake): restorable files, unusable instance."""
    root = tmp_path / "nextcloud-backup"
    _real_nextcloud(containers, root, free_port())
    containers.stop("app")
    make_readable(root)
    (root / "db" / "nextcloud.sql").unlink()
    repo = tmp_path / "repo"
    backup(repo, root)
    job, checks, _ = run_template("nextcloud", {"name": "nextcloud", "app_dir": "html", "dump_path": "db/nextcloud.sql",
                                                "pg_version": "16"}, repo)
    assert job["status"] == "failed", summary(checks)
    assert checks["postgres_dump_present:db"]["status"] == "failed"
    assert checks["file_exists:html/config/config.php"]["status"] == "passed"

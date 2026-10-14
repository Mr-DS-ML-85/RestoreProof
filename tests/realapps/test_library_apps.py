"""Library (JSON) templates against real apps: WordPress on MariaDB, Uptime Kuma v2, Grafana."""

from __future__ import annotations

import time

import httpx

from tests.realapps.conftest import backup, free_port, make_readable, run_template, summary, wait_http

WORDPRESS = "wordpress:7.1.3-apache"
MARIADB = "mariadb:11.4.13"
KUMA = "louislam/uptime-kuma:2.5.6"
GRAFANA = "grafana/grafana:13.2.4"


def test_wordpress_on_mariadb(env, tmp_path, containers):
    root = tmp_path / "wp-backup"
    html = root / "html"
    html.mkdir(parents=True)
    port = free_port()
    containers.run("db", "-e", "MARIADB_ROOT_PASSWORD=wp-root-pw", "-e", "MARIADB_DATABASE=wordpress", MARIADB)
    containers.run("wp", "-e", "WORDPRESS_DB_HOST=db", "-e", "WORDPRESS_DB_USER=root",
                   "-e", "WORDPRESS_DB_PASSWORD=wp-root-pw", "-e", "WORDPRESS_DB_NAME=wordpress",
                   "-v", f"{html}:/var/www/html", "-p", f"127.0.0.1:{port}:80", WORDPRESS)
    base = f"http://127.0.0.1:{port}"
    wait_http(f"{base}/wp-admin/install.php", timeout=300, ok=lambda r: r.status_code == 200)
    r = httpx.post(f"{base}/wp-admin/install.php?step=2", timeout=120, data={
        "weblog_title": "Family blog", "user_name": "owner", "admin_password": "wp-admin-pass-123",
        "admin_password2": "wp-admin-pass-123", "pw_weak": "on", "admin_email": "owner@example.test",
        "blog_public": "0", "language": ""})
    assert r.status_code == 200 and "Success" in r.text, r.text[:500]
    # Documented procedure: dump with --single-transaction, back up files + dump together.
    dump = containers.exec("db", "mariadb-dump", "--single-transaction", "-uroot", "-pwp-root-pw", "wordpress")
    (root / "db").mkdir()
    (root / "db" / "wordpress.sql").write_text(dump)
    make_readable(root)
    repo = tmp_path / "repo"
    backup(repo, root)
    job, checks, _ = run_template("wordpress", {"name": "blog", "db_version": "11.4"}, repo)
    assert job["status"] == "passed", summary(checks)
    assert checks["has-admin-user"]["details"]["actual"] == 1
    assert checks["mariadb_ready:db"]["details"]["server_version"].startswith("11.4")


def test_wordpress_dump_without_tables_fails(env, tmp_path, containers):
    """A dump taken from an empty database (wrong DB name in the backup script) must fail, not pass."""
    root = tmp_path / "wp-backup"
    (root / "html" / "wp-content").mkdir(parents=True)
    (root / "html" / "wp-config.php").write_text("<?php // config")
    (root / "html" / "wp-content" / "index.php").write_text("<?php")
    containers.run("db", "-e", "MARIADB_ROOT_PASSWORD=pw", "-e", "MARIADB_DATABASE=other", MARIADB)
    for _ in range(60):
        if containers.exec("db", "mariadb-admin", "ping", "-h", "127.0.0.1", "-uroot", "-ppw", check=False).strip():
            break
        time.sleep(2)
    time.sleep(3)
    dump = containers.exec("db", "mariadb-dump", "-uroot", "-ppw", "other")
    (root / "db").mkdir()
    (root / "db" / "wordpress.sql").write_text(dump)
    repo = tmp_path / "repo"
    backup(repo, root)
    job, checks, _ = run_template("wordpress", {"name": "blog", "db_version": "11.4"}, repo)
    assert job["status"] == "failed", summary(checks)
    assert checks["mysql_table_exists:db"]["status"] == "failed"
    assert "wp_" in checks["mysql_table_exists:db"]["details"]["hint"]


def test_uptime_kuma_v2(env, tmp_path, containers):
    data = tmp_path / "kuma"
    data.mkdir()
    port = free_port()
    containers.run("kuma", "-v", f"{data}:/app/data", "-p", f"127.0.0.1:{port}:3001", KUMA)
    base = f"http://127.0.0.1:{port}"
    wait_http(f"{base}/", timeout=300, ok=lambda r: r.status_code in (200, 302))
    # v2 first-run: choose the database type (SQLite) through the setup page's API, as the UI does.
    r = httpx.post(f"{base}/setup-database", json={"dbConfig": {"type": "sqlite"}}, timeout=60)
    assert r.status_code in (200, 201), r.text[:300]
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline and not (data / "kuma.db").exists():
        time.sleep(2)
    wait_http(f"{base}/api/entry-page", timeout=300, ok=lambda r: r.status_code == 200)
    time.sleep(5)
    containers.stop("kuma")
    make_readable(data)
    repo = tmp_path / "repo"
    backup(repo, data)
    # A fresh install has no monitors, so only the schema is required here.
    job, checks, _ = run_template("uptime-kuma", {"name": "kuma", "has_monitors": False}, repo)
    assert job["status"] == "passed", summary(checks)
    assert checks["sqlite_integrity:kuma.db"]["status"] == "passed"


def test_grafana_dashboards(env, tmp_path, containers):
    data = tmp_path / "grafana"
    data.mkdir()
    port = free_port()
    containers.run("grafana", "-u", "0", "-v", f"{data}:/var/lib/grafana", "-p", f"127.0.0.1:{port}:3000", GRAFANA)
    base = f"http://127.0.0.1:{port}"
    wait_http(f"{base}/api/health", timeout=300, ok=lambda r: r.status_code == 200)
    r = httpx.post(f"{base}/api/dashboards/db", auth=("admin", "admin"), timeout=30, json={
        "dashboard": {"title": "Homelab", "panels": [], "schemaVersion": 39}, "overwrite": True})
    assert r.status_code == 200, r.text
    containers.stop("grafana")
    make_readable(data)
    repo = tmp_path / "repo"
    backup(repo, data)
    job, checks, _ = run_template("grafana", {"name": "grafana"}, repo)
    assert job["status"] == "passed", summary(checks)
    assert checks["has-dashboards"]["details"]["actual"] >= 1



"""Gitea 28.1 (SQLite): the real server creates its config, database, an admin and a real Git repository."""

from __future__ import annotations

import httpx

from tests.realapps.conftest import backup, free_port, make_readable, run_template, summary, wait_http

IMAGE = "gitea/gitea:28.1.0"


def _real_gitea(containers, data, port):
    containers.run("gitea", "-e", "GITEA__security__INSTALL_LOCK=true", "-e", "GITEA__database__DB_TYPE=sqlite3",
                   "-e", "USER_UID=1000", "-e", "USER_GID=1000",
                   "-v", f"{data}:/data", "-p", f"127.0.0.1:{port}:3000", IMAGE)
    wait_http(f"http://127.0.0.1:{port}/api/healthz", ok=lambda r: r.status_code == 200)
    containers.exec("gitea", "su", "git", "-c", "gitea admin user create --admin --username owner "
                    "--password 'gitea-test-pass-1' --email owner@example.test --must-change-password=false")
    for name in ("homelab-config", "notes"):
        r = httpx.post(f"http://127.0.0.1:{port}/api/v1/user/repos", auth=("owner", "gitea-test-pass-1"),
                       json={"name": name, "auto_init": True, "readme": "Default"})
        assert r.status_code == 201, r.text


def test_gitea_backup_restores_repositories_and_database(env, tmp_path, containers):
    data = tmp_path / "gitea-data"
    data.mkdir()
    port = free_port()
    _real_gitea(containers, data, port)
    containers.stop("gitea")  # Gitea's docs: stop it (or use `gitea dump`) for a consistent backup
    make_readable(data)
    repo = tmp_path / "repo"
    backup(repo, data)
    job, checks, _ = run_template("gitea", {"name": "gitea"}, repo)
    assert job["status"] == "passed", summary(checks)
    assert checks["has-repositories"]["details"]["actual"] == 2
    assert checks["dir_not_empty:git/repositories"]["status"] == "passed"


def test_gitea_backup_missing_repositories_is_caught(env, tmp_path, containers):
    """Database backed up but the git/ volume forgotten: the web UI would list repos that no longer exist."""
    data = tmp_path / "gitea-data"
    data.mkdir()
    port = free_port()
    _real_gitea(containers, data, port)
    containers.stop("gitea")
    make_readable(data)
    repo = tmp_path / "repo"
    backup(repo, data, "--exclude", "git")
    job, checks, _ = run_template("gitea", {"name": "gitea"}, repo)
    assert job["status"] == "failed", summary(checks)
    assert checks["dir_not_empty:git/repositories"]["status"] == "failed"
    assert checks["has-repositories"]["status"] == "passed"  # the database alone looks fine

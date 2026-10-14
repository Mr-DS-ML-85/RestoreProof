"""Layers 3 and 4 against real containers: PostgreSQL import + SQL assertions, an nginx app + HTTP checks.

The key acceptance criterion for v0.2: files restore fine, but the database or app does not work -> detected.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from tests.conftest import HAS_DOCKER, REPO_PASSWORD, restic
from tests.helpers import client, make_app, make_source, run_test

pytestmark = [pytest.mark.integration, pytest.mark.docker,
              pytest.mark.skipif(not HAS_DOCKER, reason="docker daemon not available")]

GOOD_DUMP = """
CREATE ROLE app_owner;
CREATE TABLE public.users (id serial PRIMARY KEY, email text NOT NULL, created_at timestamptz DEFAULT now());
ALTER TABLE public.users OWNER TO app_owner;
INSERT INTO public.users (email) VALUES ('a@example.test'), ('b@example.test'), ('c@example.test');
CREATE TABLE public.schema_migrations (version text);
INSERT INTO public.schema_migrations VALUES ('20261001');
"""


def _snapshot(tmp_path, name: str, dump: str, html: str = "<h1>Restored OK</h1>"):
    src = tmp_path / name
    (src / "db").mkdir(parents=True)
    (src / "www").mkdir()
    (src / "db" / "dump.sql").write_text(dump)
    (src / "www" / "index.html").write_text(html)
    return src


def _definition(name: str, *, html_expect: str = "Restored OK", app_port: int = 80) -> str:
    return f"""apiVersion: restoreproof.io/v1alpha1
kind: RecoveryTest
metadata: {{name: {name}}}
spec:
  restore: {{maxDurationSeconds: 600}}
  resources:
    databases:
      - name: db
        version: "16"
        dumpPath: db/dump.sql
        database: app
        onImportError: continue
    services:
      - name: web
        image: nginx:1.27-alpine
        port: {app_port}
        mounts:
          - {{from: www, to: /usr/share/nginx/html, readOnly: true}}
        readyTimeoutSeconds: 60
  checks:
    - {{type: file_exists, path: db/dump.sql, kind: file}}
    - {{type: postgres_table_exists, target: db, table: public.users}}
    - {{type: postgres_row_count, target: db, table: public.users, min: 1}}
    - {{type: postgres_query, target: db, query: "SELECT max(version) FROM public.schema_migrations", expect: "20261001"}}
    - {{type: http, target: web, path: /, expectedStatus: 200, bodyContains: "{html_expect}"}}
"""


def _containers_for(attempt_id: str) -> list[str]:
    out = subprocess.run(["docker", "ps", "-a", "--filter", f"label=io.restoreproof.attempt={attempt_id}",
                          "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    return out.split()


def test_full_application_recovery_passes_and_cleans_up(env, tmp_path):
    repo = tmp_path / "repo"
    restic(repo, "init")
    src = _snapshot(tmp_path, "good", GOOD_DUMP)
    restic(repo, "backup", ".", cwd=src)
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), _definition("pg-app"))
    job = run_test(c, h, aid)
    checks = c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).json()
    summary = [(x["name"], x["status"], x["message"]) for x in checks]
    assert job["status"] == "passed", json.dumps(summary, indent=1)
    names = {x["name"]: x for x in checks}
    assert names["postgres_ready:db"]["details"]["server_version"].startswith("16")
    att = job["attempts"][-1]
    assert att["cleanup_status"] == "completed"
    assert _containers_for(att["id"]) == []
    report = c.get(f"/api/v1/jobs/{job['id']}/report", headers=h).json()
    assert report["verification"]["hash_ok"] and report["verification"]["signature"] == "valid"
    assert set(report["manifest"]["layers"]) >= {"recovery_point", "data", "database", "application"}


def test_files_restore_but_database_is_broken(env, tmp_path):
    """The dump exists and restores, but it is empty of the expected schema: must fail, not pass."""
    repo = tmp_path / "repo"
    restic(repo, "init")
    src = _snapshot(tmp_path, "broken-db", "-- truncated dump\nCREATE TABLE public.other (id int);\n")
    restic(repo, "backup", ".", cwd=src)
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), _definition("pg-broken"))
    job = run_test(c, h, aid)
    checks = {x["name"]: x for x in c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).json()}
    assert job["status"] == "failed"
    assert checks["file_exists:db/dump.sql"]["status"] == "passed"     # data layer is fine...
    assert checks["postgres_table_exists:db"]["status"] == "failed"     # ...database layer is not
    assert job["summary"]["layers"]["data"] == "passed"
    assert job["summary"]["layers"]["database"] == "failed"
    assert job["attempts"][-1]["cleanup_status"] == "completed"


def test_app_health_failure_detected_even_when_db_is_fine(env, tmp_path):
    repo = tmp_path / "repo"
    restic(repo, "init")
    src = _snapshot(tmp_path, "bad-app", GOOD_DUMP, html="<h1>Maintenance</h1>")
    restic(repo, "backup", ".", cwd=src)
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), _definition("app-broken"))
    job = run_test(c, h, aid)
    checks = {x["name"]: x for x in c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).json()}
    assert job["status"] == "failed"
    assert job["summary"]["layers"]["database"] == "passed"
    assert checks["http:web"]["status"] == "failed"
    assert "did not contain" in checks["http:web"]["message"]


def test_sql_assertions_are_read_only(env, tmp_path):
    """Even a query that tries to write (wrapped in a CTE) cannot modify the restored database."""
    repo = tmp_path / "repo"
    restic(repo, "init")
    src = _snapshot(tmp_path, "ro", GOOD_DUMP)
    restic(repo, "backup", ".", cwd=src)
    defn = _definition("ro-test").replace(
        "  checks:\n",
        "  checks:\n    - {type: postgres_query, target: db, name: write-attempt, required: false, "
        "query: \"WITH d AS (DELETE FROM public.users RETURNING 1) SELECT count(*) FROM d\", expect: 0}\n")
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn)
    job = run_test(c, h, aid)
    checks = {x["name"]: x for x in c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).json()}
    assert checks["write-attempt"]["status"] == "failed"
    assert "read-only" in checks["write-attempt"]["message"] or "permission" in checks["write-attempt"]["message"]
    assert checks["postgres_row_count:db"]["details"]["actual"] == 3

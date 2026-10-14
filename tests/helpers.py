from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

ADMIN = {"email": "admin@example.test", "password": "a-very-long-test-password"}


def client() -> tuple[TestClient, dict[str, str]]:
    from restoreproof.main import create_app

    c = TestClient(create_app(run_migrations=False))
    r = c.post("/api/v1/setup", json=ADMIN)
    assert r.status_code == 201, r.text
    return c, {"Authorization": f"Bearer {r.json()['token']}"}


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def file_definition(name: str, src: Path, extra_checks: str = "", recovery_point: str = "latest",
                    extra_spec: str = "", base: str = ".") -> str:
    # Our fixture backs up "." from inside the source dir, so restic stores contents at the snapshot root.
    return f"""apiVersion: restoreproof.io/v1alpha1
kind: RecoveryTest
metadata:
  name: {name}
spec:
  source:
    adapter: restic
    recoveryPoint: {recovery_point}
  restore:
    maxDurationSeconds: 300
    basePath: "{base}"
{extra_spec}
  checks:
    - type: file_exists
      path: data/important.json
      kind: file
    - type: file_hash
      path: data/notes.txt
      sha256: {sha(src / 'data' / 'notes.txt')}
    - type: file_parse
      path: data/important.json
      format: json
    - type: file_count
      path: data
      min: 2
{extra_checks}
"""


def make_source(c: TestClient, h: dict, repo: Path, password: str, name: str = "repo") -> str:
    r = c.post("/api/v1/sources", headers=h, json={"name": name, "repository": str(repo),
                                                   "credentials": {"password": password}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def make_app(c: TestClient, h: dict, source_id: str, definition: str) -> str:
    r = c.post("/api/v1/apps", headers=h, json={"source_id": source_id, "test_definition": definition})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def run_test(c: TestClient, h: dict, app_id: str, **body) -> dict:
    from restoreproof.jobs import worker

    r = c.post(f"/api/v1/apps/{app_id}/test", headers=h, json=body or None)
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    worker.run_once()
    return c.get(f"/api/v1/jobs/{job_id}", headers=h).json()

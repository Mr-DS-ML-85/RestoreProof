"""Real-application tests: each test runs the *real* upstream image to create genuine data (schema, users,
files), backs it up with restic, and runs the matching RestoreProof template against that backup.

They pull large images, so they are opt-in:   RESTOREPROOF_REALAPP_TESTS=1 pytest tests/realapps -v
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

from tests.conftest import HAS_DOCKER, HAS_RESTIC, REPO_PASSWORD, restic  # noqa: F401  (fixtures re-export)
from tests.conftest import env  # noqa: F401

ENABLED = os.environ.get("RESTOREPROOF_REALAPP_TESTS") == "1"


def pytest_collection_modifyitems(config, items):
    skip = pytest.mark.skip(reason="set RESTOREPROOF_REALAPP_TESTS=1 (pulls real application images)")
    for item in items:
        if "realapps" in str(item.fspath) and (not ENABLED or not HAS_DOCKER or not HAS_RESTIC):
            item.add_marker(skip)


def sh(*args: str, check: bool = True, timeout: int = 900) -> str:
    r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise AssertionError(f"{' '.join(args)} failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    return r.stdout


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 300, ok=lambda r: r.status_code < 500) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=5, follow_redirects=False)
            if ok(r):
                return
            last = f"HTTP {r.status_code}"
        except httpx.HTTPError as exc:
            last = type(exc).__name__
        time.sleep(2)
    raise AssertionError(f"{url} not ready after {timeout}s ({last})")


def make_readable(path: Path) -> None:
    """Containers write as root; give the files back to the test user so restic can read them, the same way a
    real backup job would run with sufficient privileges."""
    sh("docker", "run", "--rm", "-v", f"{path}:/d", "alpine:latest", "chown", "-R",
       f"{os.getuid()}:{os.getgid()}", "/d")


class Containers:
    def __init__(self):
        self.names: list[str] = []
        self.network = f"rp-real-{uuid.uuid4().hex[:8]}"
        sh("docker", "network", "create", self.network)

    def run(self, name: str, *args: str) -> str:
        full = f"{self.network}-{name}"
        sh("docker", "run", "-d", "--name", full, "--network", self.network, "--network-alias", name, *args)
        self.names.append(full)
        return full

    def exec(self, name: str, *cmd: str, check: bool = True) -> str:
        return sh("docker", "exec", f"{self.network}-{name}", *cmd, check=check)

    def stop(self, name: str, timeout: int = 90) -> None:
        sh("docker", "stop", "-t", str(timeout), f"{self.network}-{name}", timeout=timeout + 60)

    def logs(self, name: str) -> str:
        return sh("docker", "logs", "--tail", "60", f"{self.network}-{name}", check=False)

    def close(self) -> None:
        for n in reversed(self.names):
            sh("docker", "rm", "-f", "-v", n, check=False)
        sh("docker", "network", "rm", self.network, check=False)


@pytest.fixture
def containers():
    c = Containers()
    yield c
    c.close()


def backup(repo: Path, src: Path, *extra: str) -> None:
    if not (repo / "config").exists():
        restic(repo, "init")
    restic(repo, "backup", "--host", "homelab", *extra, ".", cwd=src)


def run_template(template: str, answers: dict, repo: Path):
    """Create the app from the template through the API, run one test, return (job, checks-by-name)."""
    from tests.helpers import client, make_app, make_source, run_test

    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    r = c.post(f"/api/v1/templates/{template}/render", headers=h, json={"answers": answers})
    assert r.status_code == 200, r.text
    aid = make_app(c, h, sid, r.json()["test_definition"])
    job = run_test(c, h, aid)
    checks = {x["name"]: x for x in c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).json()}
    return job, checks, (c, h, aid)


def summary(checks: dict) -> str:
    return "\n".join(f"  {v['status']:>8}  {k}: {v['message'][:140]}" for k, v in checks.items())

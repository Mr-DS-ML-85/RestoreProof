"""Protecting production: low priority, bandwidth caps, busy-host guard, maintenance window."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.conftest import REPO_PASSWORD
from tests.helpers import client, file_definition, make_app, make_source

pytestmark = pytest.mark.integration


def test_window_logic_including_midnight_wrap():
    from restoreproof.jobs.queue import in_window

    at = lambda h, m: datetime(2026, 10, 14, h, m, tzinfo=timezone.utc)  # noqa: E731
    assert in_window("", "UTC", at(12, 0))
    assert in_window("01:00-06:00", "UTC", at(3, 0)) and not in_window("01:00-06:00", "UTC", at(7, 0))
    assert in_window("22:00-04:00", "UTC", at(23, 30)) and in_window("22:00-04:00", "UTC", at(2, 0))
    assert not in_window("22:00-04:00", "UTC", at(12, 0))
    # 03:00 in Berlin (CEST, UTC+2) is 01:00 UTC
    assert in_window("02:30-03:30", "Europe/Berlin", at(1, 0))


def test_restic_runs_low_priority_with_bandwidth_cap(env, restic_repo, monkeypatch):
    from restoreproof.adapters.restic import ResticAdapter
    from restoreproof.security import process

    seen = []
    real = process.run_command

    def spy(argv, **kw):
        seen.append((list(argv), kw.get("priority")))
        return real(argv, **kw)

    monkeypatch.setattr("restoreproof.adapters.restic.run_command", spy)
    repo, _, snap = restic_repo
    ad = ResticAdapter({"repository": str(repo)}, {"password": REPO_PASSWORD}, priority="low",
                       limit_download_kib=2048)
    try:
        ad.list_recovery_points()
        dest = env.temp_root / "x"
        dest.mkdir()
        assert ad.restore_to_destination(snap, dest, include=[], timeout=60).ok
    finally:
        ad.close()
    restore = next(a for a, p in seen if "restore" in a)
    listing = next(a for a, p in seen if "snapshots" in a)
    assert ["--limit-download", "2048"] == restore[2:4]
    assert dict((a[1], p) for a, p in seen)["restore"] == "low"
    assert dict((a[1], p) for a, p in seen)["snapshots"] == "normal"  # cheap metadata calls are not slowed
    assert process.low_priority(["restic", "restore"])[:5] == ["nice", "-n", "19", "ionice", "-c"]
    assert listing


def test_busy_host_and_window_hold_back_scheduled_but_not_manual(env, restic_repo, monkeypatch):
    from sqlalchemy import select

    from restoreproof import settings_store
    from restoreproof.db.models import Job, ProtectedApp, WorkerRecord
    from restoreproof.db.session import session_scope
    from restoreproof.jobs import queue

    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("wl", src))
    with session_scope() as s:
        app = s.get(ProtectedApp, aid)
        queue.enqueue(s, app, trigger="scheduled", idempotency_key="sched:x:1")

    # Busy host: nothing is claimed and the reason is visible.
    monkeypatch.setattr(queue, "host_load", lambda: (50.0, 4))
    assert queue.claim_next("test-worker") is None
    assert "host busy" in c.get("/api/v1/workers", headers=h).json()[0]["note"]

    # Calm host but outside the window: the scheduled job waits...
    monkeypatch.setattr(queue, "host_load", lambda: (0.1, 4))
    now = datetime.now(timezone.utc)
    closed = f"{(now.hour + 2) % 24:02d}:00-{(now.hour + 3) % 24:02d}:00"
    assert c.put("/api/v1/settings/workload", headers=h,
                 json={"max_load_per_cpu": 1.5, "maintenance_window": closed, "timezone": "UTC"}).status_code == 200
    assert queue.claim_next("test-worker") is None
    with session_scope() as s:
        assert "maintenance window" in s.get(WorkerRecord, "test-worker").status_note
        # ...but a manual test is not held back by the window.
        s.scalar(select(Job).where(Job.app_id == aid)).trigger = "manual"
    assert queue.claim_next("test-worker") is not None
    with session_scope() as s:
        assert settings_store.get(s, "workload").maintenance_window == closed


def test_invalid_window_rejected(env):
    c, h = client()
    r = c.put("/api/v1/settings/workload", headers=h, json={"maintenance_window": "25:00-06:00"})
    assert r.status_code == 422

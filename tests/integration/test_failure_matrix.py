"""PRD §8.3 failure matrix against a real restic repository. None of these may ever produce a pass."""

from __future__ import annotations

import os
import stat
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text

from tests.conftest import REPO_PASSWORD, restic
from tests.helpers import client, file_definition, make_app, make_source, run_test

pytestmark = pytest.mark.integration


def _checks(c, h, job_id):
    return {x["name"]: x for x in c.get(f"/api/v1/jobs/{job_id}/checks", headers=h).json()}


def test_wrong_password_fails_without_leaking_secret(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    wrong = "totally-wrong-password-XYZ"
    aid = make_app(c, h, make_source(c, h, repo, wrong), file_definition("wrongpw", src))
    job = run_test(c, h, aid)
    assert job["status"] == "failed"
    assert job["error_code"] == "auth_failed"
    assert _checks(c, h, job["id"])["repository_access"]["status"] == "failed"
    # The secret must not appear anywhere: API, report files, logs, or plaintext DB columns.
    from restoreproof.db.session import get_engine
    blobs = [c.get(f"/api/v1/jobs/{job['id']}", headers=h).text,
             c.get(f"/api/v1/jobs/{job['id']}/report", headers=h).text,
             c.get(f"/api/v1/jobs/{job['id']}/log", headers=h).text,
             c.get("/api/v1/sources", headers=h).text,
             c.get("/api/v1/audit-events", headers=h).text]
    for p in Path(env.reports_dir).rglob("*"):
        if p.is_file():
            blobs.append(p.read_text(errors="replace"))
    with get_engine().connect() as conn:
        for table in ("check_results", "job_attempts", "jobs", "audit_events", "backup_sources"):
            blobs += [str(r) for r in conn.execute(text(f"SELECT * FROM {table}")).all()]
    assert not [b for b in blobs if wrong in b]


def test_repository_unavailable_is_inconclusive_and_retried(env, tmp_path):
    src = tmp_path / "src"
    (src / "data").mkdir(parents=True)
    (src / "data" / "notes.txt").write_text("x")
    c, h = client()
    aid = make_app(c, h, make_source(c, h, tmp_path / "does-not-exist", "pw"),
                   file_definition("norepo", src))
    job = run_test(c, h, aid)
    # First attempt hit a transient error -> job is requeued with backoff, attempt evidence kept.
    assert job["status"] == "queued" and job["trigger"] == "retry"
    assert job["attempts"][0]["status"] == "inconclusive"
    assert job["attempts"][0]["error_code"] == "repository_unavailable"
    # Make the retry runnable now and exhaust the bounded retry policy.
    from restoreproof.db.models import Job
    from restoreproof.db.session import session_scope
    from restoreproof.jobs import worker
    with session_scope() as s:
        s.get(Job, job["id"]).not_before = None
    worker.run_once()
    job = c.get(f"/api/v1/jobs/{job['id']}", headers=h).json()
    assert job["status"] == "inconclusive"
    assert [a["attempt_number"] for a in job["attempts"]] == [1, 2]


def test_missing_pinned_snapshot_fails_or_blocks_per_policy(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    aid = make_app(c, h, sid, file_definition("pinned-missing", src, recovery_point="deadbeefdeadbeef"))
    job = run_test(c, h, aid)
    assert job["status"] == "failed" and job["error_code"] == "recovery_point_missing"

    blocked = file_definition("pinned-block", src).replace(
        "    recoveryPoint: latest", "    recoveryPoint: {policy: pinned, snapshotId: deadbeefdeadbeef, onMissing: block}")
    job = run_test(c, h, make_app(c, h, sid, blocked))
    assert job["status"] == "blocked"


def test_stale_snapshot_fails_max_age_policy(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    restic(repo, "backup", "--time", "2020-01-01 00:00:00", "--host", "old", ".", cwd=src)
    defn = file_definition("maxage", src).replace(
        "    recoveryPoint: latest", "    recoveryPoint: {policy: max_age, maxAgeHours: 24, host: old}")
    job = run_test(c, h, make_app(c, h, sid, defn))
    assert job["status"] == "failed"
    assert "exceeding maxAgeHours" in _checks(c, h, job["id"])["recovery_point_selected"]["message"]


def test_rpo_breach_is_reported_but_advisory(env, restic_repo):
    repo, src, _ = restic_repo
    restic(repo, "backup", "--time", "2020-01-01 00:00:00", "--host", "old", ".", cwd=src)
    c, h = client()
    defn = file_definition("rpo", src, extra_spec="  objectives: {rpoHours: 24}").replace(
        "    recoveryPoint: latest", "    recoveryPoint: {policy: latest, host: old}")
    job = run_test(c, h, make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn))
    ch = _checks(c, h, job["id"])
    assert ch["rpo_freshness"]["status"] == "failed" and ch["rpo_freshness"]["required"] is False
    assert job["status"] == "passed"
    assert job["summary"]["layers"]["objectives"] == "warning"


def test_hash_mismatch_fails(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    defn = file_definition("hash", src, extra_checks=(
        "    - type: file_hash\n      path: config.yaml\n      sha256: '" + "0" * 64 + "'"))
    job = run_test(c, h, make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn))
    assert job["status"] == "failed"
    assert _checks(c, h, job["id"])["file_hash:config.yaml"]["status"] == "failed"


def test_missing_critical_file_fails(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    defn = file_definition("missing", src, extra_checks="    - {type: file_exists, path: data/never-backed-up.db}")
    job = run_test(c, h, make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn))
    assert job["status"] == "failed"


def test_corrupted_repository_is_not_a_pass(env, restic_repo):
    repo, src, _ = restic_repo
    for pack in (repo / "data").rglob("*"):
        if pack.is_file():
            os.chmod(pack, stat.S_IWUSR | stat.S_IRUSR)
            with open(pack, "r+b") as fh:
                fh.seek(max(0, pack.stat().st_size // 2))
                fh.write(b"\x00CORRUPTED\x00" * 4)
    c, h = client()
    defn = file_definition("corrupt", src, extra_spec="  repository: {check: true, readDataSubset: '100%'}")
    job = run_test(c, h, make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn))
    assert job["status"] in ("failed", "inconclusive")
    assert _checks(c, h, job["id"])["repository_integrity"]["status"] == "failed"


def test_restore_budget_blocks(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    defn = file_definition("budget", src).replace("    maxDurationSeconds: 300", "    maxDurationSeconds: 300\n    maxBytes: 5")
    job = run_test(c, h, make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn))
    assert job["status"] == "blocked" and job["error_code"] == "budget_exceeded"


@pytest.fixture
def slow_restic(tmp_path, monkeypatch):
    """A restic wrapper whose `restore` hangs (spawning a child, to prove the whole tree is killed)."""
    import shutil

    from restoreproof.db.session import reset_caches
    real = shutil.which("restic")
    script = tmp_path / "slow-restic"
    script.write_text(f"""#!/bin/sh
for a in "$@"; do if [ "$a" = restore ]; then sleep 600 & echo $! > {tmp_path}/child.pid; wait; fi; done
exec {real} "$@"
""")
    script.chmod(0o755)
    monkeypatch.setenv("RESTOREPROOF_RESTIC_BINARY", str(script))
    reset_caches()
    return tmp_path / "child.pid"


def test_hanging_restore_times_out_kills_tree_and_cleans_up(env, restic_repo, slow_restic):
    repo, src, _ = restic_repo
    c, h = client()
    defn = file_definition("timeout", src).replace("maxDurationSeconds: 300", "maxDurationSeconds: 10")
    t = time.monotonic()
    job = run_test(c, h, make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), defn))
    assert time.monotonic() - t < 60
    assert job["status"] == "timed_out"
    assert job["attempts"][-1]["cleanup_status"] == "completed"
    child = int(slow_restic.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)
    from restoreproof.config import get_settings
    assert list(get_settings().temp_root.iterdir()) == []


def test_cancel_running_job(env, restic_repo, slow_restic):
    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("cancel", src))
    r = c.post(f"/api/v1/apps/{aid}/test", headers=h)
    job_id = r.json()["job_id"]

    def _cancel():
        time.sleep(4)
        assert c.post(f"/api/v1/jobs/{job_id}/cancel", headers=h).status_code == 202

    th = threading.Thread(target=_cancel)
    th.start()
    from restoreproof.jobs import worker
    worker.run_once()
    th.join()
    job = c.get(f"/api/v1/jobs/{job_id}", headers=h).json()
    assert job["status"] == "cancelled"
    assert job["attempts"][-1]["cleanup_status"] == "completed"


def test_worker_crash_is_reconciled(env, restic_repo):
    """Simulate a worker that died mid-restore: stale heartbeat, half-written run dir, tracked resource."""
    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("crash", src))
    job_id = c.post(f"/api/v1/apps/{aid}/test", headers=h).json()["job_id"]
    from restoreproof.db.models import JobAttempt, utcnow
    from restoreproof.db.session import session_scope
    from restoreproof.jobs import queue, worker
    from restoreproof.runner.resources import register_resource
    from restoreproof.security.paths import create_run_dir

    _, attempt_id = queue.claim_next("dead-worker")
    d = create_run_dir(env.temp_root, attempt_id, job_id)
    register_resource(attempt_id, "directory", str(d))
    (d / "restore" / "partial.bin").write_bytes(b"x" * 100)
    with session_scope() as s:
        att = s.get(JobAttempt, attempt_id)
        att.stage, att.heartbeat_at = "restore", utcnow() - timedelta(hours=1)

    worker.reconcile()
    job = c.get(f"/api/v1/jobs/{job_id}", headers=h).json()
    assert job["attempts"][0]["status"] == "interrupted"
    assert job["attempts"][0]["cleanup_status"] == "completed"
    assert not d.exists()
    assert job["status"] == "queued"            # bounded retry
    # The retry is a *new* attempt; the interrupted one is preserved.
    from restoreproof.db.models import Job
    with session_scope() as s:
        s.get(Job, job_id).not_before = None
    worker.run_once()
    job = c.get(f"/api/v1/jobs/{job_id}", headers=h).json()
    assert job["status"] == "passed"
    assert [a["status"] for a in job["attempts"]] == ["interrupted", "passed"]


def test_cleanup_refuses_paths_outside_temp_root(env, tmp_path):
    """A tampered/forged resource record must never cause deletion outside the managed root."""
    from restoreproof.db.models import Job, JobAttempt, ManagedResource
    from restoreproof.db.session import session_scope
    from restoreproof.runner.resources import cleanup_attempt

    victim = tmp_path / "precious"
    victim.mkdir()
    (victim / "keep.txt").write_text("do not delete")
    c, h = client()
    with session_scope() as s:
        # Minimal job/attempt rows to hang the forged resource on.
        from restoreproof.db.models import BackupSource, Project, ProtectedApp
        p = Project(name="x")
        s.add(p)
        s.flush()
        src = BackupSource(project_id=p.id, name="x", adapter="restic", config_json={})
        s.add(src)
        s.flush()
        app = ProtectedApp(project_id=p.id, source_id=src.id, name="x", test_definition="", definition_sha256="0")
        s.add(app)
        s.flush()
        job = Job(app_id=app.id, definition_version=1, definition_sha256="0", status="running")
        s.add(job)
        s.flush()
        att = JobAttempt(job_id=job.id, attempt_number=1, worker_id="w")
        s.add(att)
        s.flush()
        for forged in (str(victim), str(env.temp_root / ".." / ".." / "precious"), str(env.temp_root)):
            s.add(ManagedResource(attempt_id=att.id, resource_type="directory", external_id=forged))
        aid = att.id
    status, problems = cleanup_attempt(aid, tries=1, backoff=0)
    assert status == "cleanup_failed" and len(problems) == 3
    assert (victim / "keep.txt").read_text() == "do not delete"
    assert env.temp_root.exists()


def test_scheduler_gate_and_duplicate_triggers(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("sched", src))
    r = c.put(f"/api/v1/apps/{aid}/policy", headers=h, json={"schedule": "* * * * *", "enabled": True})
    assert r.status_code == 409 and r.json()["error"]["code"] == "manual_test_required"

    # Duplicate manual requests: active lock prevents overlap; idempotency key returns the same job.
    r1 = c.post(f"/api/v1/apps/{aid}/test", headers={**h, "Idempotency-Key": "abc"})
    r2 = c.post(f"/api/v1/apps/{aid}/test", headers={**h, "Idempotency-Key": "abc"})
    r3 = c.post(f"/api/v1/apps/{aid}/test", headers=h)
    assert r1.json()["job_id"] == r2.json()["job_id"] and r2.json()["created"] is False
    assert r3.status_code == 409 and r3.json()["error"]["code"] == "job_already_active"
    from restoreproof.jobs import worker
    worker.run_once()

    assert c.put(f"/api/v1/apps/{aid}/policy", headers=h,
                 json={"schedule": "* * * * *", "enabled": True}).status_code == 200
    from restoreproof.db.models import Job, Policy
    from restoreproof.db.session import session_scope
    from restoreproof.scheduler.scheduler import tick
    with session_scope() as s:
        pol = s.scalar(select(Policy).where(Policy.app_id == aid))
        slot = pol.next_run_at
    # Two schedulers ticking for the same slot (and a later tick after downtime) create exactly one job.
    created = tick(slot + timedelta(seconds=1))
    with session_scope() as s:
        s.scalar(select(Policy).where(Policy.app_id == aid)).next_run_at = slot
    created += tick(slot + timedelta(seconds=2))
    created += tick(slot + timedelta(hours=5))
    with session_scope() as s:
        scheduled = s.scalars(select(Job).where(Job.app_id == aid, Job.trigger == "scheduled")).all()
    assert len(scheduled) == 1 and len(created) == 1

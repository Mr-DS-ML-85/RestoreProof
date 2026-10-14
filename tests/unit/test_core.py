from __future__ import annotations

import json
import os
import random
import time
from datetime import datetime, timedelta, timezone

import pytest

from restoreproof.adapters.base import RecoveryPointInfo
from restoreproof.adapters.restic import parse_restic_time
from restoreproof.definitions import DefinitionError, RecoveryPointSelection, parse_definition
from restoreproof.evidence import manifest as mf
from restoreproof.evidence.sanitization import REDACTED, Sanitizer
from restoreproof.jobs.selection import select_recovery_point
from restoreproof.jobs.state_machine import (
    JOB_TRANSITIONS,
    AttemptStatus,
    CheckOutcome,
    InvalidTransition,
    JobStatus,
    aggregate,
    assert_attempt_transition,
    assert_cleanup_transition,
    assert_job_transition,
    layer_statuses,
)
from restoreproof.security.paths import (
    UnsafePath,
    create_run_dir,
    is_owned_run_dir,
    resolve_within,
    safe_remove_run_dir,
    validate_relative,
)

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)

# -- state machine -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("src,dst", [(s, d) for s, ds in JOB_TRANSITIONS.items() for d in ds])
def test_every_allowed_job_transition(src, dst):
    assert_job_transition(src, dst)


@pytest.mark.parametrize("src", [s for s in JobStatus if s not in JOB_TRANSITIONS])
def test_terminal_job_states_are_final(src):
    for dst in JobStatus:
        with pytest.raises(InvalidTransition):
            assert_job_transition(src, dst)


def test_queued_cannot_jump_to_passed():
    with pytest.raises(InvalidTransition):
        assert_job_transition("queued", "passed")


def test_attempt_and_cleanup_transitions():
    assert_attempt_transition("running", "interrupted")
    with pytest.raises(InvalidTransition):
        assert_attempt_transition("failed", "passed")  # an old result can never be rewritten into a pass
    assert_cleanup_transition("pending", "completed")
    assert_cleanup_transition("cleanup_failed", "completed")
    with pytest.raises(InvalidTransition):
        assert_cleanup_transition("completed", "pending")


# -- aggregation (false-positive guard) ------------------------------------------------------------------------

def _o(status, required=True, layer="data"):
    return CheckOutcome(status, required, layer)


def test_aggregate_rules():
    assert aggregate([_o("passed"), _o("passed")]).status == AttemptStatus.PASSED
    assert aggregate([_o("passed"), _o("failed")]).status == AttemptStatus.FAILED
    assert aggregate([_o("passed"), _o("error")]).status == AttemptStatus.INCONCLUSIVE
    assert aggregate([_o("passed"), _o("skipped")]).status == AttemptStatus.INCONCLUSIVE
    assert aggregate([]).status == AttemptStatus.INCONCLUSIVE
    # Only advisory checks passed: nothing required was verified, so no pass.
    assert aggregate([_o("passed", required=False)]).status == AttemptStatus.INCONCLUSIVE
    # Advisory failure does not fail the run.
    assert aggregate([_o("passed"), _o("failed", required=False)]).status == AttemptStatus.PASSED
    # Failure outranks unknown.
    assert aggregate([_o("error"), _o("failed")]).status == AttemptStatus.FAILED


def test_layer_status_is_independent():
    layers = layer_statuses([_o("passed", layer="data"), _o("failed", layer="application"),
                             _o("failed", required=False, layer="objectives")])
    assert layers == {"data": "passed", "application": "failed", "objectives": "warning"}


# -- selection --------------------------------------------------------------------------------------------------

def _pts():
    return [RecoveryPointInfo(f"{i:02x}" * 32, NOW - timedelta(hours=h), "host", ["/srv"], ["daily"] if i % 2 else [])
            for i, h in enumerate([200, 50, 10, 2])]


def test_select_latest_and_filters():
    pts = _pts()
    assert select_recovery_point(pts, RecoveryPointSelection(), NOW).point == pts[-1]
    assert select_recovery_point(pts, RecoveryPointSelection(tags=["daily"]), NOW).point == pts[3]
    assert select_recovery_point(pts, RecoveryPointSelection(host="other"), NOW).point is None


def test_select_max_age():
    pts = _pts()
    assert select_recovery_point(pts, RecoveryPointSelection(policy="max_age", maxAgeHours=3), NOW).point == pts[-1]
    sel = select_recovery_point(pts[:2], RecoveryPointSelection(policy="max_age", maxAgeHours=24), NOW)
    assert sel.point is None and "exceeding" in sel.reason


def test_select_pinned_resolves_prefix_and_rejects_ambiguity():
    pts = _pts()
    sel = select_recovery_point(pts, RecoveryPointSelection(policy="pinned", snapshotId=pts[1].native_id[:8]), NOW)
    assert sel.point == pts[1]
    assert select_recovery_point(pts, RecoveryPointSelection(policy="pinned", snapshotId="ffffffff"), NOW).point is None
    dup = pts + [RecoveryPointInfo(pts[1].native_id[:8] + "ab" * 28, NOW, "host")]
    assert select_recovery_point(dup, RecoveryPointSelection(policy="pinned", snapshotId=pts[1].native_id[:8]),
                                 NOW).point is None


def test_select_random_within_window():
    pts = _pts()
    sel = select_recovery_point(pts, RecoveryPointSelection(policy="random", randomWithinDays=3), NOW,
                                rng=random.Random(1))
    assert sel.point in pts[1:] and sel.eligible_count == 3


# -- definitions --------------------------------------------------------------------------------------------------

BASE = """apiVersion: restoreproof.io/v1alpha1
kind: RecoveryTest
metadata: {name: t}
spec:
"""


def test_example_definition_from_prd_parses():
    d = parse_definition(BASE + """
  source: {adapter: restic, recoveryPoint: latest}
  restore: {mode: isolated, maxDurationSeconds: 1800, maxBytes: 5368709120}
  resources:
    databases: [{name: temporary-database, dumpPath: db/dump.sql}]
    services: [{name: temporary-application, image: "nginx:1.27-alpine", port: 80}]
  checks:
    - {type: file_exists, path: data/important.json}
    - {type: postgres_query, target: temporary-database, query: "SELECT to_regclass('public.users') IS NOT NULL", expect: true}
    - {type: http, target: temporary-application, method: GET, path: /health, expectedStatus: 200, timeoutSeconds: 10}
  cleanup: {deleteTemporaryResources: true, preserveEvidence: true}
""")
    assert len(d.spec.checks) == 3


@pytest.mark.parametrize("bad,needle", [
    ("  checks: [{type: file_exists, path: ../etc/passwd}]", "traversal"),
    ("  checks: [{type: file_exists, path: /etc/passwd}]", "absolute"),
    ("  checks: [{type: file_exists, path: '--help'}]", "start with '-'"),
    ("  checks: [{type: shell, cmd: 'rm -rf /'}]", "type"),
    ("  checks: [{type: file_exists, path: a, extra: 1}]", "Extra inputs"),
    ("  checks: [{type: http, target: nowhere, path: /}]", "not a declared service"),
    ("  resources: {databases: [{name: db, dumpPath: d.sql}]}\n  checks: [{type: postgres_query, target: db, query: 'DELETE FROM users'}]", "SELECT or WITH"),
    ("  resources: {databases: [{name: db, dumpPath: d.sql}]}\n  checks: [{type: postgres_query, target: db, query: 'SELECT 1; DROP TABLE x'}]", "single SQL"),
    ("  resources: {services: [{name: s, image: x, port: 80, mounts: [{from: a, to: /var/run/docker.sock}]}]}\n  checks: [{type: http, target: s}]", "not allowed"),
    ("  resources: {services: [{name: s, image: '-v /:/host', port: 80}]}\n  checks: [{type: http, target: s}]", "image"),
    ("  source: {recoveryPoint: {policy: pinned}}\n  checks: [{type: file_exists, path: a}]", "snapshotId"),
    ("  cleanup: {deleteTemporaryResources: false}\n  checks: [{type: file_exists, path: a}]", "deleteTemporaryResources"),
    ("  checks: []", "at least 1"),
])
def test_invalid_definitions_rejected(bad, needle):
    with pytest.raises(DefinitionError) as e:
        parse_definition(BASE + bad)
    assert needle.lower() in str(e.value).lower()


def test_not_yaml_mapping():
    with pytest.raises(DefinitionError):
        parse_definition("- a\n- b")
    with pytest.raises(DefinitionError):
        parse_definition("!!python/object:os.system {}")


# -- paths ------------------------------------------------------------------------------------------------------

def test_validate_relative():
    for ok in ("a", "a/b.txt", "./a"):
        validate_relative(ok)
    for bad in ("", "/a", "../a", "a/../../b", "-rf", "a\x00b"):
        with pytest.raises(UnsafePath):
            validate_relative(bad)


def test_resolve_within_rejects_symlinks(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.txt").write_text("x")
    (root / "link").symlink_to(tmp_path)
    (root / "inner").symlink_to(root / "ok.txt")
    assert resolve_within(root, "ok.txt") == (root / "ok.txt").resolve()
    with pytest.raises(UnsafePath):
        resolve_within(root, "link/secret")
    with pytest.raises(UnsafePath):
        resolve_within(root, "link/x", allow_symlinks=True)  # escapes root
    with pytest.raises(UnsafePath):
        resolve_within(root, "inner")
    assert resolve_within(root, "inner", allow_symlinks=True) == (root / "ok.txt").resolve()


def test_run_dir_ownership_and_safe_removal(tmp_path):
    temp = tmp_path / "temp"
    aid, jid = "11111111-2222-3333-4444-555555555555", "j"
    d = create_run_dir(temp, aid, jid)
    with pytest.raises(FileExistsError):
        create_run_dir(temp, aid, jid)  # never reused
    assert is_owned_run_dir(temp, d, aid)
    assert not is_owned_run_dir(temp, d, "99999999-2222-3333-4444-555555555555")
    # Read-only restored content must still be removable.
    (d / "restore" / "ro").mkdir()
    (d / "restore" / "ro" / "f").write_text("x")
    os.chmod(d / "restore" / "ro" / "f", 0o444)
    os.chmod(d / "restore" / "ro", 0o555)
    # A symlink inside must be unlinked, not followed.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("k")
    (d / "restore" / "escape").symlink_to(outside)
    safe_remove_run_dir(temp, d, aid)
    assert not d.exists() and (outside / "keep").exists()


def test_safe_remove_refuses_unowned(tmp_path):
    temp = tmp_path / "temp"
    temp.mkdir()
    fake = temp / "run-11111111-2222-3333-4444-555555555555"
    fake.mkdir()  # no marker
    with pytest.raises(UnsafePath):
        safe_remove_run_dir(temp, fake, "11111111-2222-3333-4444-555555555555")
    link = temp / "run-21111111-2222-3333-4444-555555555555"
    link.symlink_to(tmp_path)
    with pytest.raises(UnsafePath):
        safe_remove_run_dir(temp, link, "21111111-2222-3333-4444-555555555555")
    assert tmp_path.exists()


# -- sanitization ------------------------------------------------------------------------------------------------

def test_sanitizer_redacts_known_and_patterned_secrets():
    s = Sanitizer(["hunter2-very-secret"])
    text = ("auth with hunter2-very-secret; url=s3://AKIAABCDEFGHIJKLMNOP:pass@host; "
            "Authorization: Bearer abcdefghijklmnop; password=plain123 token: tok_abcdef "
            "rest:https://user:pw123@backup.example/repo")
    out = s.text(text)
    for leaked in ("hunter2-very-secret", "AKIAABCDEFGHIJKLMNOP", "abcdefghijklmnop", "plain123", "tok_abcdef", "pw123"):
        assert leaked not in out
    assert REDACTED in out
    assert s.obj({"password": "x", "nested": [{"api_key": "y"}], "ok": "hunter2-very-secret"}) == {
        "password": REDACTED, "nested": [{"api_key": REDACTED}], "ok": REDACTED}


# -- evidence -------------------------------------------------------------------------------------------------

def test_manifest_hash_sign_and_tamper(tmp_path):
    m = {"run_id": "r", "result": {"status": "failed"}, "checks": [{"name": "a", "status": "failed"}], "evidence": {}}
    sealed = mf.seal(m, tmp_path / "k.pem")
    v = mf.verify(sealed)
    assert v["hash_ok"] and v["signature"] == "valid"
    # Key order / whitespace does not matter (canonical form)...
    reordered = json.loads(json.dumps(sealed, indent=4, sort_keys=False))
    assert mf.verify(reordered)["hash_ok"]
    # ...but turning a failure into a pass is detected.
    forged = json.loads(json.dumps(sealed))
    forged["result"]["status"] = "passed"
    assert not mf.verify(forged)["hash_ok"]
    # Re-hashing the forgery without the key breaks the signature.
    forged["evidence"]["manifest_sha256"] = mf.manifest_hash(forged)
    assert mf.verify(forged)["signature"] == "invalid"
    assert mf.verify(sealed, trusted_fingerprint="nope")["signature"] == "valid_but_untrusted_key"


def test_parse_restic_time():
    t = parse_restic_time("2026-10-14T08:00:00.123456789+02:00")
    assert t == datetime(2026, 10, 14, 6, 0, 0, 123456, tzinfo=timezone.utc)
    assert parse_restic_time("2026-10-14T08:00:00Z").tzinfo is not None


# -- process execution --------------------------------------------------------------------------------------------

def test_command_allowlist_and_timeout(env, tmp_path, monkeypatch):
    from restoreproof.security.process import AbortRequested, CommandNotAllowed, run_command

    with pytest.raises(CommandNotAllowed):
        run_command(["sh", "-c", "echo hi"], timeout=5)
    # Allow a fake "restic" that spawns a grandchild, then verify the whole group is killed on timeout.
    fake = tmp_path / "restic"
    fake.write_text(f"#!/bin/sh\nsleep 300 & echo $! > {tmp_path}/pid\nwait\n")
    fake.chmod(0o755)
    from restoreproof.db.session import reset_caches
    monkeypatch.setenv("RESTOREPROOF_RESTIC_BINARY", str(fake))
    reset_caches()
    t = time.monotonic()
    r = run_command([str(fake)], timeout=1.5)
    assert r.timed_out and time.monotonic() - t < 10
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "pid").read_text()), 0)

    def _abort():
        raise AbortRequested("cancelled", "stop")

    r = run_command([str(fake)], timeout=30, poll=_abort, poll_interval=0.2)
    assert r.aborted and r.aborted.code == "cancelled" and not r.ok


def test_restic_adapter_refuses_destructive_subcommands(env):
    from restoreproof.adapters.base import AdapterError
    from restoreproof.adapters.restic import ResticAdapter

    ad = ResticAdapter({"repository": "/nonexistent"}, {"password": "pw"})
    try:
        for sub in ("forget", "prune", "backup", "key", "unlock", "migrate", "init"):
            with pytest.raises(AdapterError):
                ad._run(sub, [], timeout=5)
        with pytest.raises(AdapterError):
            ad.restore_to_destination("--target=/", env.temp_root, include=[], timeout=5)
        with pytest.raises(AdapterError):
            ad.restore_to_destination("abcdef12", env.temp_root, include=["--exclude=x"], timeout=5)
    finally:
        ad.close()
    with pytest.raises(AdapterError):
        ResticAdapter({"repository": "/r"}, {"password": "pw", "env": {"LD_PRELOAD": "/evil.so"}})
    with pytest.raises(AdapterError):
        ResticAdapter({"repository": "--insecure-tls"}, {"password": "pw"})

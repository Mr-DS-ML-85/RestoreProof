"""Deleting, renaming, browsing, JSON templates, import/export, demo data and help pages."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from tests.conftest import REPO_PASSWORD
from tests.helpers import client, file_definition, make_app, make_source, run_test

pytestmark = pytest.mark.integration


def _count(model) -> int:
    from restoreproof.db.session import session_scope
    with session_scope() as s:
        return s.scalar(select(func.count()).select_from(model))


# -- deleting -------------------------------------------------------------------------------------------------
def test_delete_app_keep_history_frees_name_and_keeps_runs(env, restic_repo):
    from restoreproof.db.models import CheckResult, Job
    repo, src, _ = restic_repo
    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    aid = make_app(c, h, sid, file_definition("wrongly-added", src))
    job = run_test(c, h, aid)
    r = c.delete(f"/api/v1/apps/{aid}?keep_history=true", headers=h)
    assert r.status_code == 200 and r.json()["history_kept"] and r.json()["runs"] == 1
    assert all(a["id"] != aid for a in c.get("/api/v1/apps?include_archived=true", headers=h).json())
    assert c.get(f"/api/v1/apps/{aid}", headers=h).status_code == 404
    old = c.get(f"/api/v1/jobs/{job['id']}", headers=h).json()
    assert old["status"] == "passed" and old["app_name"] == "wrongly-added (deleted)"
    assert _count(Job) == 1 and _count(CheckResult) > 0
    # the name is free again
    assert make_app(c, h, sid, file_definition("wrongly-added", src))


def test_delete_app_with_history_removes_everything(env, restic_repo):
    from restoreproof.db.models import CheckResult, EvidenceArtifact, Job, JobAttempt
    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("gone", src))
    run_test(c, h, aid)
    report_files = list(Path(env.reports_dir).rglob("manifest.json"))
    assert report_files
    r = c.delete(f"/api/v1/apps/{aid}?keep_history=false", headers=h)
    assert r.status_code == 200 and r.json()["history_kept"] is False
    assert _count(Job) == _count(JobAttempt) == _count(CheckResult) == _count(EvidenceArtifact) == 0
    assert not any(p.exists() for p in report_files)


def test_cannot_delete_app_while_test_runs(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("busy", src))
    c.post(f"/api/v1/apps/{aid}/test", headers=h)
    r = c.delete(f"/api/v1/apps/{aid}", headers=h)
    assert r.status_code == 409 and r.json()["error"]["code"] == "job_active"


def test_delete_source_blocked_while_used_then_allowed(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    aid = make_app(c, h, sid, file_definition("user-of-source", src))
    r = c.delete(f"/api/v1/sources/{sid}", headers=h)
    assert r.status_code == 409 and "user-of-source" in r.json()["error"]["message"]
    assert c.get(f"/api/v1/sources/{sid}/usage", headers=h).json()["apps"][0]["id"] == aid
    c.delete(f"/api/v1/apps/{aid}?keep_history=true", headers=h)
    r = c.delete(f"/api/v1/sources/{sid}", headers=h)
    assert r.status_code == 200
    assert c.get("/api/v1/sources", headers=h).json() == []
    assert (repo / "config").exists()  # the repository itself is untouched


def test_delete_backup_plan_and_destination(env, tmp_path):
    from restoreproof.db.models import BackupRun
    from restoreproof.jobs import worker
    data = tmp_path / "d"
    data.mkdir()
    (data / "f.txt").write_text("x")
    c, h = client()
    d = c.post("/api/v1/destinations", headers=h, json={"name": "tmp-dest", "location": {
        "type": "local", "path": str(tmp_path / "r")}}).json()
    p = c.post("/api/v1/backup-plans", headers=h, json={"name": "p", "paths": [str(data)],
                                                       "destination_ids": [d["id"]]}).json()
    c.post(f"/api/v1/backup-plans/{p['id']}/run", headers=h)
    worker.run_once()
    assert c.delete(f"/api/v1/destinations/{d['id']}", headers=h).status_code == 409  # used by the plan
    assert c.delete(f"/api/v1/backup-plans/{p['id']}", headers=h).status_code == 200
    assert _count(BackupRun) == 0
    assert c.delete(f"/api/v1/destinations/{d['id']}", headers=h).status_code == 200
    assert (tmp_path / "r" / "config").exists()  # snapshots stay


def test_rename_app_through_definition(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("typo-nmae", src))
    defn = c.get(f"/api/v1/apps/{aid}", headers=h).json()["test_definition"].replace("typo-nmae", "proper-name")
    r = c.patch(f"/api/v1/apps/{aid}", headers=h, json={"test_definition": defn})
    assert r.status_code == 200 and r.json()["name"] == "proper-name"


# -- browsing -----------------------------------------------------------------------------------------------
def test_browse_snapshot(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    root = c.get(f"/api/v1/sources/{sid}/browse?path=/", headers=h).json()
    names = {e["name"]: e["type"] for e in root["entries"]}
    assert names == {"data": "dir", "config.yaml": "file"}
    sub = c.get(f"/api/v1/sources/{sid}/browse?path=/data", headers=h).json()
    assert {e["name"] for e in sub["entries"]} == {"important.json", "notes.txt"}
    assert c.get(f"/api/v1/sources/{sid}/browse?path=../etc", headers=h).status_code == 422
    assert c.get(f"/api/v1/sources/{sid}/browse?snapshot=--help&path=/", headers=h).status_code == 422


# -- templates ------------------------------------------------------------------------------------------------
TEMPLATE = {
    "format": "restoreproof-template/v1", "id": "my-wiki", "name": "My wiki", "category": "Documents",
    "params": [{"key": "db_file", "label": "Database file", "default": "data/important.json"},
               {"key": "check_notes", "label": "Check notes", "type": "bool", "default": True},
               {"key": "extra", "label": "Extra files", "type": "list", "default": ""}],
    "definition": {"spec": {"checks": [
        {"type": "file_exists", "path": "{{db_file}}"},
        {"$if": "check_notes", "type": "file_exists", "path": "data/notes.txt"},
        {"$for": "extra", "$item": {"type": "file_exists", "path": "{{_}}"}}]}},
}


def test_custom_template_upload_render_use_export_delete(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    r = c.post("/api/v1/templates", headers=h, json=TEMPLATE)
    assert r.status_code == 201, r.text
    listed = {t["id"]: t for t in c.get("/api/v1/templates", headers=h).json()}
    assert listed["my-wiki"]["source"] == "custom" and listed["vaultwarden"]["verified"]
    y = c.post("/api/v1/templates/my-wiki/render", headers=h, json={"answers": {
        "name": "wiki", "check_notes": False, "extra": "config.yaml"}}).json()["test_definition"]
    assert "data/notes.txt" not in y and "config.yaml" in y and "inventory" in y
    job = run_test(c, h, make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), y))
    assert job["status"] == "passed"
    exported = c.get("/api/v1/templates/my-wiki/export", headers=h)
    assert exported.status_code == 200 and json.loads(exported.text)["id"] == "my-wiki"
    assert c.delete("/api/v1/templates/my-wiki", headers=h).status_code == 200
    assert "my-wiki" not in {t["id"] for t in c.get("/api/v1/templates", headers=h).json()}


@pytest.mark.parametrize("bad,code", [
    ({**TEMPLATE, "format": "nope"}, "invalid_template"),
    ({**TEMPLATE, "id": "vaultwarden"}, "reserved_id"),
    ({**TEMPLATE, "definition": {"spec": {"checks": [{"type": "file_exists", "path": "../../etc/passwd"}]}}}, "invalid_template"),
    ({**TEMPLATE, "definition": {"spec": {"checks": [{"type": "file_exists", "path": "{{missing}}"}]}}}, "invalid_template"),
])
def test_bad_templates_rejected(env, bad, code):
    c, h = client()
    r = c.post("/api/v1/templates", headers=h, json=bad)
    assert r.status_code in (409, 422) and r.json()["error"]["code"] == code, r.text


def test_app_export_import_roundtrip_and_save_as_template(env, restic_repo):
    repo, src, _ = restic_repo
    c, h = client()
    sid = make_source(c, h, repo, REPO_PASSWORD)
    aid = make_app(c, h, sid, file_definition("shared", src))
    doc = json.loads(c.get(f"/api/v1/apps/{aid}/export", headers=h).text)
    assert doc["format"] == "restoreproof-app/v1" and doc["definition"]["kind"] == "RecoveryTest"
    imp = c.post("/api/v1/apps/import", headers=h, json={"source_id": sid, "file": doc})
    assert imp.status_code == 201 and imp.json()["name"] == "shared-2" and imp.json()["renamed_from"] == "shared"
    yaml_import = c.post("/api/v1/apps/import", headers=h, json={"source_id": sid, "file": doc["test_definition_yaml"]})
    assert yaml_import.status_code == 201 and yaml_import.json()["name"] == "shared-3"
    t = c.post(f"/api/v1/apps/{aid}/save-as-template", headers=h)
    assert t.status_code == 201, t.text
    y = c.post(f"/api/v1/templates/{t.json()['id']}/render", headers=h, json={"answers": {"name": "from-tpl"}}).json()
    assert "from-tpl" in y["test_definition"]
    assert c.post("/api/v1/apps/import", headers=h, json={"source_id": sid, "file": "not: [valid"}).status_code == 422


def test_library_templates_all_valid_and_listed(env):
    from restoreproof import json_templates
    c, h = client()
    ids = {t["id"] for t in c.get("/api/v1/templates", headers=h).json()}
    for doc in json_templates.library():
        assert doc.id in ids
        json_templates.check(doc)
    assert {"wordpress", "uptime-kuma", "grafana", "pihole", "jellyfin", "mariadb-app"} <= ids


# -- demo ---------------------------------------------------------------------------------------------------
def test_demo_passes_then_break_fails_with_hints_then_repair_passes(env):
    from restoreproof.jobs import worker
    c, h = client()
    r = c.post("/api/v1/demo", headers=h)
    assert r.status_code == 201, r.text
    worker.run_once()
    job = c.get(f"/api/v1/jobs/{r.json()['job_id']}", headers=h).json()
    assert job["status"] == "passed", c.get(f"/api/v1/jobs/{job['id']}/checks", headers=h).text
    assert c.post("/api/v1/demo", headers=h).json()["created"] is False  # idempotent
    assert c.post("/api/v1/demo/break", headers=h).status_code == 200
    j2 = run_test(c, h, r.json()["app_id"])
    checks = {x["name"]: x for x in c.get(f"/api/v1/jobs/{j2['id']}/checks", headers=h).json()}
    assert j2["status"] == "failed"
    assert checks["all-notes-present"]["status"] == "failed"
    assert checks["sqlite_integrity:notes.db"]["status"] == "failed" and checks["sqlite_integrity:notes.db"]["details"]["hint"]
    c.post("/api/v1/demo/repair", headers=h)
    assert run_test(c, h, r.json()["app_id"])["status"] == "passed"


def test_help_pages(env):
    c, h = client()
    topics = c.get("/api/v1/help").json()["topics"]
    assert len(topics) == 5
    for t in topics:
        page = c.get(f"/api/v1/help/{t['id']}").json()
        assert page["markdown"].startswith("# ")
    assert c.get("/api/v1/help/../../etc/passwd").status_code == 404

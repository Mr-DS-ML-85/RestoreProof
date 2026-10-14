"""Templates gallery, trusted baselines, instance settings, readiness report, diagnostics."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

import yaml

from restoreproof import audit, diagnostics, json_templates, settings_store
from restoreproof.api.deps import ApiError, current_user, db, get_or_404, require
from restoreproof.db.models import (
    Baseline,
    CustomTemplate,
    EvidenceArtifact,
    Job,
    JobAttempt,
    Policy,
    ProtectedApp,
    User,
    utcnow,
)
from restoreproof.definitions import DefinitionError
from restoreproof.evidence import readiness
from restoreproof.jobs.state_machine import TERMINAL_JOB
from restoreproof.remediation import CHECK_HINTS, ERROR_HINTS
from restoreproof.templates import TEMPLATES, describe, render

router = APIRouter(prefix="/api/v1", tags=["product"])


# -- templates ---------------------------------------------------------------------------------------------------
# Three kinds: built-in (Python, verified against real apps), library (JSON files shipped with RestoreProof) and
# custom (JSON uploaded by you or saved from one of your applications). All render the same way.
VERIFIED_BUILTIN = {
    "vaultwarden": "Vaultwarden 1.37.4", "gitea": "Gitea 28.1", "immich": "Immich v3.3.1",
    "nextcloud": "Nextcloud 35.0.1", "paperless-ngx": "Paperless-ngx 3.3.1", "home-assistant": "Home Assistant 2026.10.1",
}


def _all_docs(s: Session) -> dict[str, tuple[str, Any]]:
    out: dict[str, tuple[str, Any]] = {}
    for doc in json_templates.library():
        out[doc.id] = ("library", doc)
    for row in s.scalars(select(CustomTemplate)).all():
        try:
            out[row.template_id] = ("custom", json_templates.load_doc(row.content))
        except json_templates.TemplateError:
            continue
    return out


@router.get("/templates")
def list_templates(s: Session = Depends(db), _: User = Depends(current_user)) -> list[dict[str, Any]]:
    out = []
    for t in describe():
        t.update(source="builtin", exportable=False, verified=VERIFIED_BUILTIN.get(t["id"], ""))
        out.append(t)
    for tid, (kind, doc) in _all_docs(s).items():
        if tid in TEMPLATES:
            continue
        out.append(json_templates.describe(doc, source=kind))
    return out


@router.post("/templates/{template_id}/render")
def render_template(template_id: str, body: dict, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    answers = body.get("answers") if isinstance(body.get("answers"), dict) else {}
    try:
        if template_id in TEMPLATES:
            return {"test_definition": render(template_id, answers)}
        docs = _all_docs(s)
        if template_id not in docs:
            raise ApiError(404, "not_found", f"template {template_id} does not exist")
        return {"test_definition": json_templates.render(docs[template_id][1], answers)}
    except DefinitionError as exc:
        raise ApiError(422, "invalid_answers", "the answers produce an invalid definition", exc.errors) from exc
    except json_templates.TemplateError as exc:
        raise ApiError(422, "invalid_template", str(exc), exc.errors) from exc
    except ValueError as exc:
        raise ApiError(422, "invalid_answers", str(exc)) from exc


@router.post("/templates", status_code=201)
def upload_template(body: dict, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    """Add a template from its JSON (format restoreproof-template/v1). Replaces your own template with the
    same id; built-in and library ids are reserved."""
    try:
        doc = json_templates.load_doc(body)
        json_templates.check(doc)
    except json_templates.TemplateError as exc:
        raise ApiError(422, "invalid_template", str(exc), exc.errors) from exc
    if doc.id in TEMPLATES or any(d.id == doc.id for d in json_templates.library()):
        raise ApiError(409, "reserved_id", f"'{doc.id}' is a built-in template id; choose another id")
    row = s.scalar(select(CustomTemplate).where(CustomTemplate.template_id == doc.id))
    if row:
        row.content = doc.model_dump()
    else:
        s.add(CustomTemplate(template_id=doc.id, content=doc.model_dump(), created_by=user.id))
    audit.record(s, "template.saved", actor=user, details={"id": doc.id, "name": doc.name, "replaced": bool(row)})
    return json_templates.describe(doc, source="custom")


@router.get("/templates/{template_id}/export")
def export_template(template_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> Response:
    docs = _all_docs(s)
    if template_id not in docs:
        raise ApiError(404, "not_exportable", "built-in templates are written in Python; create an application from "
                                              "it and use 'Save as my template' to get an editable JSON copy")
    return Response(json.dumps(docs[template_id][1].model_dump(), indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{template_id}.template.json"'})


@router.delete("/templates/{template_id}")
def delete_template(template_id: str, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    row = s.scalar(select(CustomTemplate).where(CustomTemplate.template_id == template_id))
    if row is None:
        raise ApiError(404, "not_found", "only your own templates can be deleted")
    s.delete(row)
    audit.record(s, "template.deleted", actor=user, details={"id": template_id})
    return {"deleted": True}


# -- application export / import ------------------------------------------------------------------------------
@router.get("/apps/{app_id}/export")
def export_app(app_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> Response:
    app = get_or_404(s, ProtectedApp, app_id, "application")
    pol = s.scalar(select(Policy).where(Policy.app_id == app.id))
    doc = {"format": "restoreproof-app/v1", "exported_at": utcnow().isoformat(), "name": app.name,
           "description": app.description, "definition": yaml.safe_load(app.test_definition),
           "test_definition_yaml": app.test_definition,
           "schedule": {"cron": pol.schedule, "timezone": pol.timezone, "max_age_last_success_hours":
                        pol.max_age_last_success_hours} if pol else None}
    return Response(json.dumps(doc, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{app.name}.restoreproof.json"'})


@router.post("/apps/import", status_code=201)
def import_app(body: dict, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    """Create an application from an exported file. Accepts {"source_id", "file"} where file is the exported
    JSON object, a RecoveryTest as JSON, or YAML text."""
    from restoreproof.api.routes_apps import AppIn, create_app
    src_id, f = body.get("source_id"), body.get("file")
    if not src_id or f is None:
        raise ApiError(422, "invalid_request", "source_id and file are required")
    if isinstance(f, str):
        try:
            f = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ApiError(422, "invalid_file", f"not valid JSON or YAML: {exc}") from exc
    if not isinstance(f, dict):
        raise ApiError(422, "invalid_file", "the file must contain an object")
    if f.get("format") == "restoreproof-template/v1":
        raise ApiError(422, "is_template", "this is a template file; upload it under 'My templates' instead")
    definition = f.get("definition") if f.get("format") == "restoreproof-app/v1" else f
    if not isinstance(definition, dict) or definition.get("kind") != "RecoveryTest":
        raise ApiError(422, "invalid_file", "no RecoveryTest definition found in this file")
    definition = copy.deepcopy(definition)
    base = json_templates.slug(definition.get("metadata", {}).get("name", "imported"))
    name, n = base, 2
    while s.scalar(select(ProtectedApp).where(ProtectedApp.name == name)):
        name, n = f"{base[:36]}-{n}", n + 1
    definition.setdefault("metadata", {})["name"] = name
    text = "# Imported " + utcnow().strftime("%Y-%m-%d") + "\n" + yaml.safe_dump(definition, sort_keys=False)
    out = create_app(AppIn(source_id=src_id, test_definition=text), s, user)
    out["renamed_from"] = base if name != base else None
    return out


@router.post("/apps/{app_id}/save-as-template", status_code=201)
def save_app_as_template(app_id: str, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    app = get_or_404(s, ProtectedApp, app_id, "application")
    tid = json_templates.slug(app.name)
    if tid in TEMPLATES or any(d.id == tid for d in json_templates.library()):
        tid = f"my-{tid}"[:40]
    doc = json_templates.from_app(app.name, app.test_definition, template_id=tid)
    try:
        json_templates.check(doc)
    except json_templates.TemplateError as exc:
        raise ApiError(422, "invalid_template", str(exc), exc.errors) from exc
    return upload_template(doc.model_dump(), s, user)


@router.get("/remediation")
def remediation(_: User = Depends(current_user)) -> dict:
    return {"errors": ERROR_HINTS, "checks": CHECK_HINTS}


# -- baselines ---------------------------------------------------------------------------------------------------
def _baseline_out(b: Baseline) -> dict[str, Any]:
    return {"id": b.id, "check_name": b.check_name, "file_count": b.file_count, "total_bytes": b.total_bytes,
            "recovery_point": b.recovery_point_native_id, "approved_at": b.approved_at, "active": b.active,
            "sha256": b.sha256, "source_attempt_id": b.source_attempt_id}


@router.get("/apps/{app_id}/baselines")
def list_baselines(app_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> list:
    get_or_404(s, ProtectedApp, app_id, "application")
    rows = s.scalars(select(Baseline).where(Baseline.app_id == app_id).order_by(Baseline.approved_at.desc())).all()
    return [_baseline_out(b) for b in rows]


@router.post("/apps/{app_id}/baselines", status_code=201)
def approve_baseline(app_id: str, body: dict, s: Session = Depends(db), user: User = Depends(require("admin"))) -> list:
    """Approve the inventories observed in a finished run as the trusted reference for later runs."""
    app = get_or_404(s, ProtectedApp, app_id, "application")
    job = get_or_404(s, Job, str(body.get("job_id") or ""), "job")
    if job.app_id != app.id:
        raise ApiError(422, "wrong_app", "that run belongs to a different application")
    if job.status not in TERMINAL_JOB:
        raise ApiError(409, "not_finished", "only finished runs can become a baseline")
    att = s.scalars(select(JobAttempt).where(JobAttempt.job_id == job.id)
                    .order_by(JobAttempt.attempt_number.desc()).limit(1)).first()
    arts = s.scalars(select(EvidenceArtifact).where(EvidenceArtifact.attempt_id == att.id,
                                                    EvidenceArtifact.artifact_type == "inventory",
                                                    EvidenceArtifact.purged_at.is_(None))).all() if att else []
    if not arts:
        raise ApiError(409, "no_inventory", "this run recorded no inventory (add an `inventory` check first, "
                                            "or the inventory file was removed by retention)")
    created = []
    for art in arts:
        src = Path(art.storage_path)
        raw = src.read_bytes() if src.is_file() else b""
        if not raw or hashlib.sha256(raw).hexdigest() != art.sha256:
            raise ApiError(409, "artifact_changed", f"inventory for {art.name} is missing or was modified")
        data = json.loads(raw)
        for old in s.scalars(select(Baseline).where(Baseline.app_id == app.id, Baseline.check_name == art.name,
                                                    Baseline.active.is_(True))).all():
            old.active = False
        b = Baseline(app_id=app.id, check_name=art.name or "inventory", source_attempt_id=att.id,
                     recovery_point_native_id=att.recovery_point_native_id, storage_path=str(src),
                     content=gzip.compress(raw), sha256=art.sha256, file_count=len(data["files"]),
                     total_bytes=sum(v[0] for v in data["files"].values()), approved_by=user.id)
        s.add(b)
        s.flush()
        created.append(_baseline_out(b))
        audit.record(s, "baseline.approved", actor=user, target_type="app", target_id=app.id,
                     details={"check": b.check_name, "job_id": job.id, "files": b.file_count,
                              "recovery_point": b.recovery_point_native_id, "run_status": job.status})
    return created


# -- settings ----------------------------------------------------------------------------------------------------
@router.get("/settings")
def get_instance_settings(s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    return settings_store.all_settings(s)


@router.put("/settings/{key}")
def put_instance_setting(key: str, body: dict, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    if key not in settings_store.MODELS:
        raise ApiError(404, "not_found", f"unknown settings group {key}")
    before = settings_store.get(s, key).model_dump()
    try:
        obj = settings_store.put(s, key, body, user.id)
    except Exception as exc:  # pydantic ValidationError
        raise ApiError(422, "invalid_settings", str(exc)) from exc
    audit.record(s, "settings.updated", actor=user, details={"group": key, "before": before, "after": obj.model_dump()})
    return obj.model_dump()


# -- readiness report -----------------------------------------------------------------------------------------
@router.get("/readiness-report")
def readiness_report(format: str = "json", days: int = 30, s: Session = Depends(db),
                     _: User = Depends(current_user)):
    days = max(1, min(days, 365))
    rep = readiness.build(s, days)
    if format == "html":
        footer = settings_store.get(s, "organization").report_footer
        return HTMLResponse(readiness.render_html(rep, footer), headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    if format == "download":
        return Response(json.dumps(rep, indent=2), media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="readiness-{utcnow().strftime("%Y%m%d")}.json"'})
    return rep


# -- diagnostics ------------------------------------------------------------------------------------------------
@router.get("/diagnostics")
def get_diagnostics(_: User = Depends(require("operator"))) -> dict:
    items = diagnostics.run()
    return {"status": diagnostics.summary(items), "items": items}


# -- demo -------------------------------------------------------------------------------------------------------
@router.post("/demo", status_code=201)
def create_demo(s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    """Create demo data (sample app + real restic backup + source + test) and queue the first test."""
    from restoreproof import demo
    from restoreproof.jobs.queue import ActiveJobExists, enqueue
    try:
        out = demo.create(s, user)
    except demo.DemoError as exc:
        raise ApiError(409, "demo_unavailable", str(exc)) from exc
    s.flush()
    if out["created"]:
        try:
            job, _ = enqueue(s, s.get(ProtectedApp, out["app_id"]), trigger="manual", requested_by=user)
            out["job_id"] = job.id
        except ActiveJobExists as exc:
            out["job_id"] = exc.job_id
    else:  # already there: show the latest run instead of starting another one
        latest = s.scalars(select(Job).where(Job.app_id == out["app_id"]).order_by(Job.created_at.desc()).limit(1)).first()
        out["job_id"] = latest.id if latest else None
    s.commit()
    return out


@router.post("/demo/break")
def break_demo(s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    from restoreproof import demo
    try:
        return demo.break_demo(s, user)
    except demo.DemoError as exc:
        raise ApiError(409, "demo_unavailable", str(exc)) from exc


@router.post("/demo/repair")
def repair_demo(s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    from restoreproof import demo
    try:
        return demo.repair_demo(s, user)
    except demo.DemoError as exc:
        raise ApiError(409, "demo_unavailable", str(exc)) from exc


# -- in-app help -------------------------------------------------------------------------------------------
HELP_TOPICS = {"getting-started": "Getting started", "writing-tests": "Writing a test", "templates": "Templates",
               "backups": "Backups", "troubleshooting": "When a test fails"}


@router.get("/help")
def help_index() -> dict:
    return {"topics": [{"id": k, "title": v} for k, v in HELP_TOPICS.items()]}


@router.get("/help/{topic}")
def help_topic(topic: str) -> dict:
    from importlib import resources
    if topic not in HELP_TOPICS:
        raise ApiError(404, "not_found", "no such help page")
    return {"id": topic, "title": HELP_TOPICS[topic],
            "markdown": (resources.files("restoreproof") / "help" / f"{topic}.md").read_text()}

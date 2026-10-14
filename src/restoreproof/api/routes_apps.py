from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from restoreproof import audit
from restoreproof.api.deps import ApiError, current_user, db, default_project, get_or_404, require
from restoreproof.api.schemas import AppIn, AppPatch, PolicyIn, TestRequest
from restoreproof.db.models import Baseline, BackupSource, Job, Policy, ProtectedApp, TestDefinitionVersion, User, utcnow
from restoreproof.definitions import DefinitionError, definition_sha256, json_schema, parse_definition
from restoreproof.jobs.queue import ActiveJobExists, enqueue
from restoreproof.scheduler.scheduler import next_after, validate_schedule

router = APIRouter(prefix="/api/v1", tags=["apps"])


def _validate(text: str):
    try:
        return parse_definition(text)
    except DefinitionError as exc:
        raise ApiError(422, "invalid_definition", "the test definition failed validation", exc.errors) from exc


def _last(s: Session, app_id: str, status: str | None = None) -> Job | None:
    q = select(Job).where(Job.app_id == app_id)
    if status:
        q = q.where(Job.status == status)
    return s.scalars(q.order_by(Job.created_at.desc()).limit(1)).first()


def job_brief(j: Job | None) -> dict | None:
    if j is None:
        return None
    return {"id": j.id, "status": j.status, "recovery_status": j.recovery_status, "cleanup_status": j.cleanup_status,
            "created_at": j.created_at, "finished_at": j.finished_at, "trigger": j.trigger,
            "error_code": j.error_code, "summary": j.summary_json}


def configured_layers(d) -> list[str]:
    layers = ["recovery_point", "data"]
    if d.spec.resources.databases or any(c.type.startswith(("postgres", "sqlite", "mysql")) for c in d.spec.checks):
        layers.append("database")
    if d.spec.resources.services:
        layers.append("application")
    return layers


def app_out(s: Session, app: ProtectedApp, full: bool = False) -> dict[str, Any]:
    policy = s.scalar(select(Policy).where(Policy.app_id == app.id))
    d = parse_definition(app.test_definition)
    out: dict[str, Any] = {
        "id": app.id, "name": app.name, "description": app.description, "source_id": app.source_id,
        "definition_version": app.definition_version, "definition_sha256": app.definition_sha256,
        "archived": app.archived, "created_at": app.created_at, "updated_at": app.updated_at,
        "latest_job": job_brief(_last(s, app.id)), "last_passed_job": job_brief(_last(s, app.id, "passed")),
        "policy": policy_out(policy),
        "layers_configured": configured_layers(d),
        "has_inventory": any(c.type == "inventory" for c in d.spec.checks),
        "active_baselines": s.scalar(select(func.count()).select_from(Baseline).where(
            Baseline.app_id == app.id, Baseline.active.is_(True))) or 0,
    }
    if full:
        out["test_definition"] = app.test_definition
        out["objectives"] = d.spec.objectives.model_dump()
        out["recovery_point_policy"] = d.spec.source.recoveryPoint.model_dump()
        out["limits"] = {"maxDurationSeconds": d.spec.restore.maxDurationSeconds, "maxBytes": d.spec.restore.maxBytes}
        out["check_count"] = len(d.spec.checks)
        out["resources"] = {"databases": [x.name for x in d.spec.resources.databases],
                            "services": [x.name for x in d.spec.resources.services]}
    return out


def policy_out(p: Policy | None) -> dict | None:
    if p is None:
        return None
    return {"schedule": p.schedule, "timezone": p.timezone, "enabled": p.enabled, "jitter_seconds": p.jitter_seconds,
            "max_age_last_success_hours": p.max_age_last_success_hours, "next_run_at": p.next_run_at,
            "last_scheduled_at": p.last_scheduled_at}


@router.get("/schema/recovery-test")
def definition_schema() -> dict:
    return json_schema()


@router.post("/definitions/validate")
def validate_definition(body: dict, _: User = Depends(current_user)) -> dict:
    text = body.get("test_definition")
    if not isinstance(text, str):
        raise ApiError(422, "invalid_request", "test_definition (string) is required")
    d = _validate(text)
    return {"valid": True, "name": d.metadata.name, "checks": len(d.spec.checks)}


@router.get("/apps")
def list_apps(include_archived: bool = False, s: Session = Depends(db), _: User = Depends(current_user)) -> list:
    q = select(ProtectedApp).where(ProtectedApp.deleted_at.is_(None)).order_by(ProtectedApp.name)
    if not include_archived:
        q = q.where(ProtectedApp.archived.is_(False))
    return [app_out(s, a) for a in s.scalars(q).all()]


@router.post("/apps", status_code=201)
def create_app(body: AppIn, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    get_or_404(s, BackupSource, body.source_id, "source")
    d = _validate(body.test_definition)
    if s.scalar(select(ProtectedApp).where(ProtectedApp.name == d.metadata.name)):
        raise ApiError(409, "conflict", f"an application named {d.metadata.name!r} already exists")
    sha = definition_sha256(body.test_definition)
    app = ProtectedApp(project_id=default_project(s).id, source_id=body.source_id, name=d.metadata.name,
                       description=d.metadata.description, test_definition=body.test_definition,
                       definition_version=1, definition_sha256=sha)
    s.add(app)
    s.flush()
    s.add(TestDefinitionVersion(app_id=app.id, version=1, yaml=body.test_definition, sha256=sha, created_by=user.id))
    s.add(Policy(app_id=app.id))
    s.flush()
    audit.record(s, "app.created", actor=user, target_type="app", target_id=app.id,
                 details={"name": app.name, "definition_sha256": sha})
    return app_out(s, app, full=True)


def _live_app(s: Session, app_id: str) -> ProtectedApp:
    app = get_or_404(s, ProtectedApp, app_id, "application")
    if app.deleted_at is not None:
        raise ApiError(404, "not_found", "this application was deleted (its past runs are still listed under Runs)")
    return app


@router.get("/apps/{app_id}")
def get_app(app_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    return app_out(s, _live_app(s, app_id), full=True)


@router.delete("/apps/{app_id}")
def delete_app(app_id: str, keep_history: bool = True, s: Session = Depends(db),
               user: User = Depends(require("admin"))) -> dict:
    """Delete an application. keep_history=true keeps past results and reports; false removes them too."""
    from restoreproof import deletion
    try:
        return deletion.delete_app(s, _live_app(s, app_id), keep_history=keep_history, actor=user)
    except deletion.Blocked as exc:
        raise ApiError(409, exc.code, str(exc), exc.details) from exc


@router.patch("/apps/{app_id}")
def patch_app(app_id: str, body: AppPatch, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    app = _live_app(s, app_id)
    details: dict[str, Any] = {}
    if body.source_id:
        get_or_404(s, BackupSource, body.source_id, "source")
        details["source_id"] = [app.source_id, body.source_id]
        app.source_id = body.source_id
    if body.test_definition is not None:
        d = _validate(body.test_definition)
        if d.metadata.name != app.name:
            clash = s.scalar(select(ProtectedApp).where(ProtectedApp.name == d.metadata.name, ProtectedApp.id != app.id))
            if clash:
                raise ApiError(409, "conflict", f"another application is already called {d.metadata.name!r}")
            details["renamed"] = [app.name, d.metadata.name]
            app.name = d.metadata.name
        sha = definition_sha256(body.test_definition)
        if sha != app.definition_sha256:
            app.definition_version += 1
            app.test_definition, app.definition_sha256 = body.test_definition, sha
            app.description = d.metadata.description
            s.add(TestDefinitionVersion(app_id=app.id, version=app.definition_version, yaml=body.test_definition,
                                        sha256=sha, created_by=user.id))
            details["definition"] = {"version": app.definition_version, "sha256": sha}
    if body.archived is not None:
        app.archived = body.archived
        details["archived"] = body.archived
    app.updated_at = utcnow()
    audit.record(s, "app.updated", actor=user, target_type="app", target_id=app.id, details=details)
    return app_out(s, app, full=True)


@router.get("/apps/{app_id}/versions")
def versions(app_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> list:
    get_or_404(s, ProtectedApp, app_id, "application")
    rows = s.scalars(select(TestDefinitionVersion).where(TestDefinitionVersion.app_id == app_id)
                     .order_by(TestDefinitionVersion.version.desc())).all()
    return [{"version": r.version, "sha256": r.sha256, "created_at": r.created_at, "yaml": r.yaml} for r in rows]


@router.post("/apps/{app_id}/test", status_code=202)
def request_test(app_id: str, body: TestRequest | None = None, s: Session = Depends(db),
                 user: User = Depends(require("operator")),
                 idempotency_key: str | None = Header(default=None, max_length=200)) -> JSONResponse:
    app = _live_app(s, app_id)
    if app.archived:
        raise ApiError(409, "archived", "archived applications cannot be tested")
    body = body or TestRequest()
    try:
        job, created = enqueue(s, app, trigger="manual", requested_by=user,
                               idempotency_key=f"manual:{user.id}:{idempotency_key}" if idempotency_key else None,
                               pinned_recovery_point=body.recovery_point)
    except ActiveJobExists as exc:
        raise ApiError(409, "job_already_active", "this application already has a queued or running test",
                       {"job_id": exc.job_id}) from exc
    except ValueError as exc:
        raise ApiError(422, "idempotency_conflict", str(exc)) from exc
    s.commit()  # durably queued before we answer 202
    return JSONResponse(status_code=202, content={
        "job_id": job.id, "status": job.status, "app_id": app.id, "created_at": job.created_at.isoformat(),
        "status_url": f"/api/v1/jobs/{job.id}", "created": created})


@router.get("/apps/{app_id}/policy")
def get_policy(app_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict | None:
    get_or_404(s, ProtectedApp, app_id, "application")
    return policy_out(s.scalar(select(Policy).where(Policy.app_id == app_id)))


@router.put("/apps/{app_id}/policy")
def put_policy(app_id: str, body: PolicyIn, s: Session = Depends(db), user: User = Depends(require("admin"))) -> dict:
    app = get_or_404(s, ProtectedApp, app_id, "application")
    try:
        validate_schedule(body.schedule, body.timezone)
    except Exception as exc:  # noqa: BLE001
        raise ApiError(422, "invalid_schedule", str(exc)) from exc
    if body.enabled:
        # Safety gate: no scheduled resource-intensive work before a human has run and reviewed one test.
        manual_done = s.scalar(select(Job.id).where(Job.app_id == app.id, Job.trigger.in_(["manual", "retry"]),
                                                    Job.finished_at.is_not(None)).limit(1))
        if not manual_done:
            raise ApiError(409, "manual_test_required",
                           "run and review a manual test before enabling the schedule")
    p = s.scalar(select(Policy).where(Policy.app_id == app.id))
    if p is None:
        p = Policy(app_id=app.id)
        s.add(p)
    before = policy_out(p)
    for k, v in body.model_dump().items():
        setattr(p, k, v)
    p.next_run_at = next_after(p, utcnow()) if p.enabled else None
    audit.record(s, "policy.updated", actor=user, target_type="app", target_id=app.id,
                 details={"before": before, "after": body.model_dump()})
    return policy_out(p)

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from restoreproof.api.deps import ApiError, current_user, db, get_or_404, page, require
from restoreproof.config import get_settings
from restoreproof.db.models import (
    CheckResult,
    EvidenceArtifact,
    Job,
    JobAttempt,
    ManagedResource,
    ProtectedApp,
    User,
)
from restoreproof.evidence.manifest import verify
from restoreproof.jobs.queue import request_cancel
from restoreproof.jobs.state_machine import TERMINAL_JOB

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])


def _latest_attempt(s: Session, job: Job) -> JobAttempt | None:
    return s.scalars(select(JobAttempt).where(JobAttempt.job_id == job.id)
                     .order_by(JobAttempt.attempt_number.desc()).limit(1)).first()


def attempt_out(s: Session, a: JobAttempt) -> dict[str, Any]:
    resources = s.scalars(select(ManagedResource).where(ManagedResource.attempt_id == a.id)).all()
    artifacts = s.scalars(select(EvidenceArtifact).where(EvidenceArtifact.attempt_id == a.id)).all()
    return {
        "id": a.id, "attempt_number": a.attempt_number, "worker_id": a.worker_id, "status": a.status,
        "stage": a.stage, "started_at": a.started_at, "finished_at": a.finished_at, "heartbeat_at": a.heartbeat_at,
        "cleanup_status": a.cleanup_status, "evidence_status": a.evidence_status,
        "recovery_point": {"native_id": a.recovery_point_native_id, "created_at": a.recovery_point_time},
        "restored_files": a.restored_files, "restored_bytes": a.restored_bytes, "timings_ms": a.timings_json,
        "stages": a.stages_json, "error_code": a.error_code, "error_message": a.error_message,
        "resources": [{"type": r.resource_type, "external_id": r.external_id if r.resource_type != "directory"
                       else Path(r.external_id).name, "cleanup_status": r.cleanup_status,
                       "cleanup_error": r.cleanup_error} for r in resources],
        "artifacts": [{"id": e.id, "type": e.artifact_type, "sha256": e.sha256, "size_bytes": e.size_bytes,
                       "created_at": e.created_at} for e in artifacts],
    }


def job_out(s: Session, j: Job, detail: bool = False) -> dict[str, Any]:
    app = s.get(ProtectedApp, j.app_id)
    app_name = (app.name.split("~deleted-")[0] + " (deleted)") if app and app.deleted_at else (app.name if app else None)
    out = {"id": j.id, "app_id": j.app_id, "app_name": app_name, "app_deleted": bool(app and app.deleted_at),
           "status": j.status,
           "recovery_status": j.recovery_status, "cleanup_status": j.cleanup_status, "trigger": j.trigger,
           "created_at": j.created_at, "started_at": j.started_at, "finished_at": j.finished_at,
           "attempt_count": j.attempt_count, "cancel_requested": j.cancel_requested,
           "definition_version": j.definition_version, "pinned_recovery_point": j.pinned_recovery_point,
           "error_code": j.error_code, "error_message": j.error_message, "summary": j.summary_json,
           "not_before": j.not_before}
    if detail:
        attempts = s.scalars(select(JobAttempt).where(JobAttempt.job_id == j.id)
                             .order_by(JobAttempt.attempt_number)).all()
        out["attempts"] = [attempt_out(s, a) for a in attempts]
    return out


@router.get("")
def list_jobs(app_id: str | None = None, status: str | None = None, limit: int = 50, offset: int = 0,
              s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    limit, offset = page(limit, offset)
    q = select(Job)
    if app_id:
        q = q.where(Job.app_id == app_id)
    if status:
        q = q.where(Job.status.in_(status.split(",")))
    total = s.scalar(select(func.count()).select_from(q.subquery()))
    rows = s.scalars(q.order_by(Job.created_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [job_out(s, j) for j in rows]}


@router.get("/{job_id}")
def get_job(job_id: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    return job_out(s, get_or_404(s, Job, job_id, "job"), detail=True)


@router.post("/{job_id}/cancel", status_code=202)
def cancel(job_id: str, s: Session = Depends(db), user: User = Depends(require("operator"))) -> dict:
    job = get_or_404(s, Job, job_id, "job")
    if job.status in TERMINAL_JOB:
        raise ApiError(409, "already_finished", f"job is already {job.status}")
    request_cancel(s, job, user)
    return job_out(s, job)


@router.get("/{job_id}/checks")
def checks(job_id: str, attempt: int | None = None, s: Session = Depends(db), _: User = Depends(current_user)) -> list:
    job = get_or_404(s, Job, job_id, "job")
    q = select(JobAttempt).where(JobAttempt.job_id == job.id)
    q = q.where(JobAttempt.attempt_number == attempt) if attempt else q.order_by(JobAttempt.attempt_number.desc())
    att = s.scalars(q.limit(1)).first()
    if att is None:
        return []
    rows = s.scalars(select(CheckResult).where(CheckResult.attempt_id == att.id).order_by(CheckResult.seq)).all()
    return [{"seq": r.seq, "layer": r.layer, "name": r.name, "type": r.check_type, "required": r.required,
             "status": r.status, "message": r.message, "duration_ms": r.duration_ms, "details": r.details_json,
             "attempt_number": att.attempt_number} for r in rows]


def _artifact(s: Session, job: Job, kind: str, attempt: int | None) -> EvidenceArtifact:
    q = select(JobAttempt).where(JobAttempt.job_id == job.id)
    q = q.where(JobAttempt.attempt_number == attempt) if attempt else q.order_by(JobAttempt.attempt_number.desc())
    for att in s.scalars(q).all():
        art = s.scalars(select(EvidenceArtifact).where(EvidenceArtifact.attempt_id == att.id,
                                                       EvidenceArtifact.artifact_type == kind)
                        .order_by(EvidenceArtifact.created_at.desc()).limit(1)).first()
        if art:
            return art
    raise ApiError(404, "no_report", "no report has been produced for this job yet")


def _safe_path(art: EvidenceArtifact) -> Path:
    p = Path(art.storage_path).resolve()
    root = get_settings().reports_dir.resolve()
    if root not in p.parents or not p.is_file():
        raise ApiError(410, "artifact_missing", "the evidence file is no longer available")
    return p


@router.get("/{job_id}/report")
def report(job_id: str, format: str = "json", attempt: int | None = None, download: bool = False,
           s: Session = Depends(db), _: User = Depends(current_user)):
    job = get_or_404(s, Job, job_id, "job")
    if format == "html":
        art = _artifact(s, job, "report_html", attempt)
        return HTMLResponse(_safe_path(art).read_text(), headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    if format != "json":
        raise ApiError(422, "invalid_format", "format must be json or html")
    art = _artifact(s, job, "manifest", attempt)
    path = _safe_path(art)
    if download:
        return FileResponse(path, media_type="application/json", filename=f"restoreproof-{job.id}.json")
    data = json.loads(path.read_text())
    return JSONResponse({"manifest": data, "verification": verify(data), "artifact_sha256": art.sha256})


@router.get("/{job_id}/log")
def run_log(job_id: str, attempt: int | None = None, s: Session = Depends(db),
            _: User = Depends(require("operator"))) -> dict:
    job = get_or_404(s, Job, job_id, "job")
    art = _artifact(s, job, "log", attempt)
    text = _safe_path(art).read_text(errors="replace")
    limit = get_settings().log_tail_bytes
    return {"sha256": art.sha256, "truncated": len(text) > limit, "text": text[-limit:]}


@router.get("/{job_id}/compare")
def compare(job_id: str, other: str, s: Session = Depends(db), _: User = Depends(current_user)) -> dict:
    """Per-check differences between two runs (e.g. last pass vs current failure)."""
    a_job, b_job = get_or_404(s, Job, job_id, "job"), get_or_404(s, Job, other, "job")

    def _checks(job: Job) -> dict[str, dict]:
        att = _latest_attempt(s, job)
        if not att:
            return {}
        return {r.name: {"status": r.status, "message": r.message} for r in s.scalars(
            select(CheckResult).where(CheckResult.attempt_id == att.id)).all()}

    a, b = _checks(a_job), _checks(b_job)
    rows = []
    for name in sorted(set(a) | set(b)):
        if a.get(name, {}).get("status") != b.get(name, {}).get("status"):
            rows.append({"check": name, "this": a.get(name), "other": b.get(name)})
    return {"job": job_id, "other": other, "changed": rows, "this_status": a_job.status, "other_status": b_job.status}

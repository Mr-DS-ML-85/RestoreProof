"""Metadata schema.

Rules enforced here (see PRD §10):
- UUID primary keys, UTC timestamps, integer millisecond durations.
- Evidence (jobs, attempts, checks, artifacts) is never cascade-deleted. Applications are archived, not deleted.
- Each execution attempt is a separate row so retries never overwrite earlier evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    BigInteger,
    LargeBinary,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stores aware datetimes as UTC and always returns aware UTC datetimes (SQLite drops tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not allowed; use UTC-aware values")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {datetime: UTCDateTime, dict[str, Any]: JSON, list[Any]: JSON}


def _pk() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=new_id)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _pk()
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | operator | viewer
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[str] = _pk()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(100), default="session")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200), unique=True)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class StoredSecret(Base):
    """Encrypted credential material. Kept apart from ordinary configuration; referenced by secret_ref."""

    __tablename__ = "secrets"
    id: Mapped[str] = _pk()
    ciphertext: Mapped[str] = mapped_column(Text)
    key_fingerprint: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class BackupSource(Base):
    __tablename__ = "backup_sources"
    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(200), unique=True)
    adapter: Mapped[str] = mapped_column(String(32))
    config_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    secret_ref: Mapped[str | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
    last_validated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_validation_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_validation_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_discovered_at: Mapped[datetime | None] = mapped_column(nullable=True)


class RecoveryPoint(Base):
    __tablename__ = "recovery_points"
    __table_args__ = (UniqueConstraint("source_id", "native_id", name="uq_recovery_point_native"),)
    id: Mapped[str] = _pk()
    source_id: Mapped[str] = mapped_column(ForeignKey("backup_sources.id"))
    native_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column()
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    paths: Mapped[list[Any]] = mapped_column(default=list)
    tags: Mapped[list[Any]] = mapped_column(default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    discovered_at: Mapped[datetime] = mapped_column(default=utcnow)
    # False once a later discovery no longer lists it (e.g. pruned by the backup tool's own retention).
    present: Mapped[bool] = mapped_column(Boolean, default=True)


class ProtectedApp(Base):
    __tablename__ = "protected_apps"
    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    # NULL only for deleted apps whose source was removed later; live apps always have a source.
    source_id: Mapped[str | None] = mapped_column(ForeignKey("backup_sources.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    # Set when the user deleted the app but chose to keep its test history (the row stays for the jobs).
    deleted_at: Mapped[datetime | None] = mapped_column(nullable=True)
    test_definition: Mapped[str] = mapped_column(Text)
    definition_version: Mapped[int] = mapped_column(Integer, default=1)
    definition_sha256: Mapped[str] = mapped_column(String(64))
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class TestDefinitionVersion(Base):
    """Every saved revision of an app's YAML, so old reports always point at the definition they ran."""

    __tablename__ = "test_definition_versions"
    __table_args__ = (UniqueConstraint("app_id", "version", name="uq_definition_version"),)
    id: Mapped[str] = _pk()
    app_id: Mapped[str] = mapped_column(ForeignKey("protected_apps.id"))
    version: Mapped[int] = mapped_column(Integer)
    yaml: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = _pk()
    app_id: Mapped[str] = mapped_column(ForeignKey("protected_apps.id"), unique=True)
    schedule: Mapped[str] = mapped_column(String(100), default="0 3 * * *")  # cron expression
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    jitter_seconds: Mapped[int] = mapped_column(Integer, default=0)
    # A test is "overdue" when the last passed run is older than this.
    max_age_last_success_hours: Mapped[int] = mapped_column(Integer, default=48)
    limits_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    next_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    overdue_notified_at: Mapped[datetime | None] = mapped_column(nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = _pk()
    app_id: Mapped[str] = mapped_column(ForeignKey("protected_apps.id"))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # manual | scheduled | retry
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), unique=True, nullable=True)
    # Equals app_id while the job is non-terminal, NULL afterwards. The unique constraint makes it impossible
    # to have two active jobs for the same app, even with racing schedulers or duplicate API calls.
    active_lock: Mapped[str | None] = mapped_column(String(36), unique=True, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    definition_version: Mapped[int] = mapped_column(Integer)
    definition_sha256: Mapped[str] = mapped_column(String(64))
    pinned_recovery_point: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    not_before: Mapped[datetime | None] = mapped_column(nullable=True)
    recovery_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cleanup_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    summary_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class JobAttempt(Base):
    __tablename__ = "job_attempts"
    __table_args__ = (UniqueConstraint("job_id", "attempt_number", name="uq_attempt_number"),)
    id: Mapped[str] = _pk()
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    attempt_number: Mapped[int] = mapped_column(Integer)
    worker_id: Mapped[str] = mapped_column(String(200))
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    heartbeat_at: Mapped[datetime] = mapped_column(default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="running")
    stage: Mapped[str] = mapped_column(String(32), default="starting")
    cleanup_status: Mapped[str] = mapped_column(String(16), default="pending")
    evidence_status: Mapped[str] = mapped_column(String(16), default="pending")
    recovery_point_native_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recovery_point_time: Mapped[datetime | None] = mapped_column(nullable=True)
    restore_dir: Mapped[str | None] = mapped_column(Text, nullable=True)
    restored_files: Mapped[int | None] = mapped_column(Integer, nullable=True)
    restored_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    timings_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    stages_json: Mapped[list[Any]] = mapped_column(default=list)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class CheckResult(Base):
    __tablename__ = "check_results"
    id: Mapped[str] = _pk()
    attempt_id: Mapped[str] = mapped_column(ForeignKey("job_attempts.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    layer: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(200))
    check_type: Mapped[str] = mapped_column(String(48))
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16))  # passed | failed | error | skipped
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")
    details_json: Mapped[dict[str, Any]] = mapped_column(default=dict)


class ManagedResource(Base):
    __tablename__ = "managed_resources"
    id: Mapped[str] = _pk()
    attempt_id: Mapped[str] = mapped_column(ForeignKey("job_attempts.id"), index=True)
    resource_type: Mapped[str] = mapped_column(String(16))  # directory | container | network
    external_id: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    cleanup_status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    cleanup_attempts: Mapped[int] = mapped_column(Integer, default=0)
    cleanup_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cleaned_at: Mapped[datetime | None] = mapped_column(nullable=True)


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"
    id: Mapped[str] = _pk()
    attempt_id: Mapped[str] = mapped_column(ForeignKey("job_attempts.id"), index=True)
    artifact_type: Mapped[str] = mapped_column(String(32))  # manifest | report_html | log
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    storage_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Set when the retention policy removed the file. The row (and its sha256) is kept as a record.
    purged_at: Mapped[datetime | None] = mapped_column(nullable=True)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)


class Baseline(Base):
    """An inventory an administrator approved as the trusted reference for later runs."""

    __tablename__ = "baselines"
    id: Mapped[str] = _pk()
    app_id: Mapped[str] = mapped_column(ForeignKey("protected_apps.id"), index=True)
    check_name: Mapped[str] = mapped_column(String(200))
    source_attempt_id: Mapped[str] = mapped_column(ForeignKey("job_attempts.id"))
    recovery_point_native_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Where the inventory came from (the run's evidence file). The trusted copy itself lives in `content`.
    storage_path: Mapped[str] = mapped_column(Text)
    # gzip-compressed inventory JSON, kept in the database so it is covered by the metadata backup and needs
    # no filesystem write access from the API.
    content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    sha256: Mapped[str] = mapped_column(String(64))
    file_count: Mapped[int] = mapped_column(Integer)
    total_bytes: Mapped[int] = mapped_column(BigInteger)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime] = mapped_column(default=utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class BackupPlan(Base):
    """What to back up, where to (ordered destinations: first that fits wins), when, and how long to keep it."""

    __tablename__ = "backup_plans"
    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(100), unique=True)
    paths: Mapped[list[Any]] = mapped_column(default=list)
    excludes: Mapped[list[Any]] = mapped_column(default=list)
    # Ordered list of backup_sources.id (destinations). Local ones are used only if the space guard passes.
    destination_ids: Mapped[list[Any]] = mapped_column(default=list)
    hooks: Mapped[list[Any]] = mapped_column(default=list)
    retention: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Never fill a local disk beyond this: keep max(min_free_percent of the disk, global MIN_FREE_BYTES) free.
    min_free_percent: Mapped[int] = mapped_column(Integer, default=10)
    schedule: Mapped[str] = mapped_column(String(100), default="0 2 * * *")
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Recovery tests (protected_apps.id) queued automatically after each successful backup.
    verify_app_ids: Mapped[list[Any]] = mapped_column(default=list)
    next_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class BackupRun(Base):
    __tablename__ = "backup_runs"
    id: Mapped[str] = _pk()
    plan_id: Mapped[str] = mapped_column(ForeignKey("backup_plans.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued|running|succeeded|failed|blocked
    trigger: Mapped[str] = mapped_column(String(16), default="manual")
    idempotency_key: Mapped[str | None] = mapped_column(String(200), unique=True, nullable=True)
    active_lock: Mapped[str | None] = mapped_column(String(36), unique=True, nullable=True)
    destination_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Why this destination was chosen (or every destination rejected): list of {destination, verdict, reason}.
    decision: Mapped[list[Any]] = mapped_column(default=list)
    snapshot_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_added: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    files_new: Mapped[int | None] = mapped_column(Integer, nullable=True)
    files_changed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retention_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    verify_job_ids: Mapped[list[Any]] = mapped_column(default=list)
    worker_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(nullable=True)
    log_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class CustomTemplate(Base):
    """A user-uploaded (or saved-from-app) JSON template, format restoreproof-template/v1."""

    __tablename__ = "custom_templates"
    id: Mapped[str] = _pk()
    template_id: Mapped[str] = mapped_column(String(64), unique=True)
    content: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class AppSetting(Base):
    """Instance-wide settings editable in the dashboard (retention, defaults)."""

    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = _pk()
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_label: Mapped[str] = mapped_column(String(320), default="system")
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    details_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class NotificationEndpoint(Base):
    __tablename__ = "notification_endpoints"
    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(200))
    type: Mapped[str] = mapped_column(String(16))  # webhook | email | ntfy
    config_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    secret_ref: Mapped[str | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    events: Mapped[list[Any]] = mapped_column(default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_delivery_status: Mapped[str | None] = mapped_column(String(200), nullable=True)


class WorkerRecord(Base):
    __tablename__ = "workers"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    heartbeat_at: Mapped[datetime] = mapped_column(default=utcnow)
    offline_notified: Mapped[bool] = mapped_column(Boolean, default=False)
    # Why the worker is not starting tests right now (host busy, outside maintenance window), if anything.
    status_note: Mapped[str | None] = mapped_column(String(300), nullable=True)

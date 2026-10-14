"""API request/response models. Secrets are write-only: they appear in requests, never in responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SetupIn(In):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+$", max_length=320)
    password: str = Field(min_length=12, max_length=1024)


class LoginIn(In):
    email: str
    password: str


class UserIn(In):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+$", max_length=320)
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["viewer", "operator", "admin"] = "viewer"


class ResticCredentials(In):
    password: str = Field(min_length=1, max_length=4096)
    env: dict[str, str] = {}


class SourceIn(In):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$")
    adapter: Literal["restic"] = "restic"
    repository: str = Field(min_length=1, max_length=2048, pattern=r"^[^-\x00\n][^\x00\n]*$")
    credentials: ResticCredentials


class SourcePatch(In):
    name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$")
    repository: str | None = Field(default=None, min_length=1, max_length=2048, pattern=r"^[^-\x00\n][^\x00\n]*$")
    credentials: ResticCredentials | None = None


class AppIn(In):
    source_id: str
    test_definition: str = Field(min_length=1, max_length=128 * 1024)


class AppPatch(In):
    source_id: str | None = None
    test_definition: str | None = Field(default=None, min_length=1, max_length=128 * 1024)
    archived: bool | None = None


class TestRequest(In):
    recovery_point: str | None = Field(default=None, pattern=r"^[0-9a-f]{8,64}$")
    acknowledge_resource_usage: bool = False


class PolicyIn(In):
    schedule: str = Field(default="0 3 * * *", max_length=100)
    timezone: str = Field(default="UTC", max_length=64)
    enabled: bool = False
    jitter_seconds: int = Field(default=0, ge=0, le=6 * 3600)
    max_age_last_success_hours: int = Field(default=48, ge=1, le=24 * 365)


class NotificationIn(In):
    name: str = Field(min_length=1, max_length=200)
    type: Literal["webhook", "email", "ntfy"]
    config: dict[str, Any] = {}
    secret: dict[str, str] = {}
    events: list[str] = ["recovery_failed", "cleanup_failed", "source_failure", "test_overdue", "worker_offline"]
    enabled: bool = True


class JobAccepted(BaseModel):
    job_id: str
    status: str
    app_id: str
    created_at: datetime
    status_url: str
    created: bool

"""Instance settings editable from the dashboard, with typed defaults."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from restoreproof.db.models import AppSetting


class Retention(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Sanitized run logs are the bulkiest artifact and the most likely to contain incidental detail.
    log_days: int = Field(default=30, ge=1, le=3650)
    # Manifests + HTML reports. 0 = keep forever. The latest passing report of every app is always kept.
    report_days: int = Field(default=0, ge=0, le=36500)
    inventory_days: int = Field(default=90, ge=1, le=3650)


class Organization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Shown on readiness reports (e.g. the homelab or the customer the report is for).
    name: str = Field(default="", max_length=200)
    report_footer: str = Field(default="", max_length=500)


class Workload(BaseModel):
    """Keeps recovery tests from degrading production services on the same host."""

    model_config = ConfigDict(extra="forbid")
    # Do not start a test while the 1-minute load average exceeds this many times the CPU count. 0 = off.
    max_load_per_cpu: float = Field(default=1.5, ge=0, le=100)
    # "HH:MM-HH:MM" (may wrap midnight). Scheduled tests only start inside it; manual tests always may.
    maintenance_window: str = Field(default="", pattern=r"^$|^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$")
    timezone: str = Field(default="UTC", max_length=64)


MODELS: dict[str, type[BaseModel]] = {"retention": Retention, "organization": Organization, "workload": Workload}


def get(session: Session, key: str) -> BaseModel:
    model = MODELS[key]
    row = session.get(AppSetting, key)
    return model.model_validate(row.value if row else {})


def put(session: Session, key: str, value: dict[str, Any], user_id: str | None) -> BaseModel:
    obj = MODELS[key].model_validate(value)
    row = session.get(AppSetting, key)
    if row is None:
        session.add(AppSetting(key=key, value=obj.model_dump(), updated_by=user_id))
    else:
        row.value, row.updated_by = obj.model_dump(), user_id
    return obj


def all_settings(session: Session) -> dict[str, Any]:
    return {k: get(session, k).model_dump() for k in MODELS}

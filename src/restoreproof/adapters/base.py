"""Backup adapter interface. Hides tool syntax, not differences in what each tool's checks guarantee."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


class AdapterError(Exception):
    """A classified, already-sanitized adapter failure."""

    def __init__(self, code: str, message: str, *, transient: bool = False, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.transient = transient
        self.details = details or {}


@dataclass(frozen=True)
class RecoveryPointInfo:
    native_id: str
    created_at: datetime
    hostname: str | None = None
    paths: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class OperationResult:
    ok: bool
    duration_ms: int
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    log: str = ""


class BackupAdapter(ABC):
    name: str
    #: What each operation actually establishes. Copied into every report so readers know the limits.
    guarantees: dict[str, str] = {}

    @abstractmethod
    def tool_version(self) -> str: ...

    @abstractmethod
    def validate_credentials(self) -> OperationResult: ...

    @abstractmethod
    def list_recovery_points(self) -> list[RecoveryPointInfo]: ...

    @abstractmethod
    def get_recovery_point_metadata(self, native_id: str) -> RecoveryPointInfo: ...

    @abstractmethod
    def estimate_restore_size(self, native_id: str, timeout: float) -> int | None: ...

    @abstractmethod
    def check_repository(self, *, read_data_subset: str | None, timeout: float,
                         poll: Callable[[], None] | None = None) -> OperationResult: ...

    @abstractmethod
    def restore_to_destination(self, native_id: str, destination: Path, *, include: list[str],
                               timeout: float, poll: Callable[[], None] | None = None) -> OperationResult: ...

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release any temporary credential material."""

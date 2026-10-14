"""Runtime settings, read from environment variables (prefix RESTOREPROOF_)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

VERSION = "0.3.0"


def _env(name: str, default: str) -> str:
    return os.environ.get(f"RESTOREPROOF_{name}", default)


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_url: str
    # Root under which every temporary restore destination is created. Nothing outside it is ever deleted.
    temp_root: Path
    reports_dir: Path
    # Encryption key for stored credentials. Lives outside the metadata database on purpose.
    secret_key_file: Path
    # Ed25519 key for signing report manifests. Keep a copy of the public key fingerprint elsewhere.
    signing_key_file: Path
    sign_reports: bool
    restic_binary: str
    docker_binary: str
    http_probe_image: str
    worker_id: str
    worker_poll_seconds: float
    heartbeat_seconds: float
    # An attempt whose heartbeat is older than this is considered abandoned by a dead worker.
    stale_attempt_seconds: float
    max_concurrent_jobs: int
    min_free_bytes: int
    max_attempts: int
    base_url: str
    # Apply migrations automatically on start-up. Compose disables it and uses a one-shot `migrate` service.
    auto_migrate: bool = True
    log_tail_bytes: int = 256 * 1024
    rclone_binary: str = "rclone"
    allowed_executables: frozenset[str] = field(default_factory=frozenset)


@lru_cache
def get_settings() -> Settings:
    data_dir = Path(_env("DATA_DIR", "./data")).resolve()
    restic = _env("RESTIC_BINARY", "restic")
    docker = _env("DOCKER_BINARY", "docker")
    rclone = _env("RCLONE_BINARY", "rclone")
    return Settings(
        data_dir=data_dir,
        database_url=_env("DATABASE_URL", f"sqlite:///{data_dir / 'restoreproof.db'}"),
        temp_root=Path(_env("TEMP_ROOT", str(data_dir / "temporary"))).resolve(),
        reports_dir=Path(_env("REPORTS_DIR", str(data_dir / "reports"))).resolve(),
        secret_key_file=Path(_env("SECRET_KEY_FILE", str(data_dir / "secrets" / "restoreproof.key"))).resolve(),
        signing_key_file=Path(_env("SIGNING_KEY_FILE", str(data_dir / "secrets" / "signing-ed25519.pem"))).resolve(),
        sign_reports=_env("SIGN_REPORTS", "true").lower() in ("1", "true", "yes"),
        restic_binary=restic,
        docker_binary=docker,
        http_probe_image=_env("HTTP_PROBE_IMAGE", "curlimages/curl:8.10.1"),
        worker_id=_env("WORKER_ID", f"{os.uname().nodename}-{os.getpid()}"),
        worker_poll_seconds=float(_env("WORKER_POLL_SECONDS", "2")),
        heartbeat_seconds=float(_env("HEARTBEAT_SECONDS", "10")),
        stale_attempt_seconds=float(_env("STALE_ATTEMPT_SECONDS", "120")),
        max_concurrent_jobs=int(_env("MAX_CONCURRENT_JOBS", "1")),
        min_free_bytes=int(_env("MIN_FREE_BYTES", str(1024**3))),
        max_attempts=int(_env("MAX_ATTEMPTS", "2")),
        base_url=_env("BASE_URL", "http://localhost:8080").rstrip("/"),
        auto_migrate=_env("AUTO_MIGRATE", "true").lower() in ("1", "true", "yes"),
        rclone_binary=rclone,
        allowed_executables=frozenset({restic, docker, rclone}),
    )


def ensure_dirs(settings: Settings) -> None:
    """Best effort: read-only components (web, scheduler in compose) cannot and need not create these."""
    for d in (settings.data_dir, settings.temp_root, settings.reports_dir):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    try:
        settings.secret_key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        pass

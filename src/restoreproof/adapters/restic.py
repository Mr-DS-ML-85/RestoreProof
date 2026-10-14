"""Restic adapter: native CLI as a subprocess with argv arrays, a controlled environment and timeouts.

Only read-oriented subcommands are allowlisted. `forget`, `prune`, `backup`, `key`, `unlock`, `migrate`, ...
can never be issued by this module.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from restoreproof.adapters.base import AdapterError, BackupAdapter, OperationResult, RecoveryPointInfo
from restoreproof.config import get_settings
from restoreproof.evidence.sanitization import Sanitizer, truncate
from restoreproof.security.process import AbortRequested, CommandResult, run_command

ALLOWED_SUBCOMMANDS = frozenset({"version", "cat", "snapshots", "stats", "check", "restore", "ls"})
SNAPSHOT_ID_RE = re.compile(r"^[0-9a-f]{8,64}$")
# Backend credential variables a source may supply through its encrypted secret.
ALLOWED_BACKEND_ENV = frozenset({
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION", "AWS_PROFILE",
    "B2_ACCOUNT_ID", "B2_ACCOUNT_KEY", "AZURE_ACCOUNT_NAME", "AZURE_ACCOUNT_KEY", "AZURE_ACCOUNT_SAS",
    "GOOGLE_PROJECT_ID", "GOOGLE_APPLICATION_CREDENTIALS", "RESTIC_REST_USERNAME", "RESTIC_REST_PASSWORD",
    "OS_AUTH_URL", "OS_USERNAME", "OS_PASSWORD", "OS_TENANT_NAME", "OS_REGION_NAME",
})
REPO_RE = re.compile(r"^(?!-)[^\x00\n]{1,2048}$")


def parse_restic_time(value: str) -> datetime:
    # restic emits RFC3339 with nanoseconds, e.g. 2026-10-14T08:00:00.123456789+02:00
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$", value)
    if not m:
        raise ValueError(f"unrecognised timestamp {value!r}")
    base, frac, tz = m.groups()
    frac = (frac or ".0")[:7]
    tz = "+00:00" if tz == "Z" else tz
    return datetime.fromisoformat(f"{base}{frac}{tz}")


def classify_failure(result: CommandResult) -> AdapterError:
    err = result.stderr.lower()
    if result.timed_out:
        return AdapterError("timeout", "restic did not finish within the time limit", transient=True)
    if result.aborted:
        return AdapterError(result.aborted.code, str(result.aborted))
    rc = result.returncode
    if rc == 12 or "wrong password" in err or "no key found" in err:
        return AdapterError("auth_failed", "repository password is incorrect (no matching key)")
    if rc == 10 or "repository does not exist" in err or "unable to open config file" in err:
        return AdapterError("repository_unavailable", "repository does not exist or cannot be opened",
                            transient=True)
    if rc == 11 or "unable to create lock" in err or "repository is already locked" in err:
        return AdapterError("repository_locked", "repository is locked by another process", transient=True)
    if "no such host" in err or "connection refused" in err or "timeout" in err or "i/o timeout" in err:
        return AdapterError("repository_unavailable", "repository backend unreachable", transient=True)
    if "no matching id found" in err or "no snapshot found" in err:
        return AdapterError("recovery_point_missing", "snapshot not found in repository")
    return AdapterError("adapter_error", f"restic exited with code {rc}")


class ResticAdapter(BackupAdapter):
    name = "restic"
    #: Recovery tests may only read. The backup module uses ResticWriter (restoreproof.backups.writer).
    allowed_subcommands = ALLOWED_SUBCOMMANDS
    guarantees = {
        "check_repository": "Structural check of repository metadata and index. Without readDataSubset it does "
                            "not read or decrypt file data.",
        "check_repository_read_data": "Reads and verifies the selected fraction of pack files against their "
                                      "hashes. Unread packs are not verified.",
        "restore_to_destination": "Extracts the snapshot and (restic --verify) re-reads restored files to "
                                  "confirm they match the snapshot. This proves the data matches what was "
                                  "backed up, not that the backed-up data was correct or complete.",
    }

    def __init__(self, config: dict[str, Any], secret: dict[str, Any], sanitizer: Sanitizer | None = None,
                 *, priority: str = "normal", limit_download_kib: int | None = None):
        self.priority = priority
        self.limit_download_kib = limit_download_kib
        password = secret.get("password")
        if not isinstance(password, str) or not password:
            raise AdapterError("invalid_config", "source secret needs a 'password'")
        extra_env = secret.get("env") or {}
        bad = set(extra_env) - ALLOWED_BACKEND_ENV
        if bad:
            raise AdapterError("invalid_config", f"unsupported backend variables: {sorted(bad)}")
        self.sanitizer = sanitizer or Sanitizer()
        self.sanitizer.add(password, *[str(v) for v in extra_env.values()])
        settings = get_settings()
        # Prefer RAM-backed storage so a crash never leaves the password on persistent disk.
        shm = "/dev/shm" if os.access("/dev/shm", os.W_OK) else None
        self._secret_dir = Path(tempfile.mkdtemp(prefix="rp-secret-", dir=shm))
        os.chmod(self._secret_dir, 0o700)
        self._options: list[str] = []
        location_env: dict[str, str] = {}
        if config.get("location"):
            from restoreproof.backups import locations
            try:
                loc = locations.parse(config["location"])
                res = locations.resolve(loc, secret.get("location_secret") or {}, self._secret_dir,
                                        rclone_binary=settings.rclone_binary, obscure=self._rclone_obscure)
            except (ValueError, TypeError) as exc:
                self.close()
                raise AdapterError("invalid_config", f"destination is misconfigured: {exc}") from exc
            for name, content in res.files.items():
                self._write_private(name, content)
            repo, location_env, self._options = res.repository, res.env, res.options
            self.sanitizer.add(*[str(v) for v in (secret.get("location_secret") or {}).values() if isinstance(v, str)],
                               *[v for k, v in location_env.items() if k.endswith(("PASS", "TOKEN", "KEY", "PASSWORD"))])
        else:
            repo = config.get("repository")
            if not isinstance(repo, str) or not REPO_RE.match(repo):
                self.close()
                raise AdapterError("invalid_config", "source config needs a 'repository' string")
        self.repository = repo
        pw_file = self._write_private("password", password)
        cache = settings.data_dir / "cache" / "restic"
        cache.mkdir(parents=True, exist_ok=True)
        self._env = {
            "RESTIC_REPOSITORY": repo,
            "RESTIC_PASSWORD_FILE": str(pw_file),
            "RESTIC_CACHE_DIR": str(cache),
            "RESTIC_PROGRESS_FPS": "0.016",
            **location_env,
            **{k: str(v) for k, v in extra_env.items()},
        }
        self._binary = settings.restic_binary

    def _write_private(self, name: str, content: str) -> Path:
        path = self._secret_dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        return path

    @staticmethod
    def _rclone_obscure(plain: str) -> str:
        """rclone stores passwords obscured; the plain text goes in via stdin, never argv."""
        r = run_command([get_settings().rclone_binary, "obscure", "-"], timeout=30, stdin_data=plain.encode())
        if not r.ok:
            raise ValueError("rclone is required for this destination but `rclone obscure` failed: "
                             + (r.stderr.strip()[:200] or "not installed?"))
        return r.stdout.strip()

    def close(self) -> None:
        if getattr(self, "_secret_dir", None):
            shutil.rmtree(self._secret_dir, ignore_errors=True)

    def __del__(self) -> None:  # best effort, close() is the real path
        try:
            self.close()
        except Exception:
            pass

    # -- internals -----------------------------------------------------------------------------------------
    def _run(self, sub: str, args: list[str], *, timeout: float, poll: Callable[[], None] | None = None,
             no_lock: bool = True, json_out: bool = True) -> CommandResult:
        if sub not in self.allowed_subcommands:
            raise AdapterError("command_not_allowed", f"restic {sub} is not permitted")
        argv = [self._binary, sub]
        for opt in self._options:
            argv += ["-o", opt]
        if self.limit_download_kib:
            argv += ["--limit-download", str(int(self.limit_download_kib))]
        if no_lock:
            argv.append("--no-lock")
        if json_out:
            argv.append("--json")
        argv += args
        heavy = sub in ("restore", "check", "stats")
        return run_command(argv, timeout=timeout, env=self._env, poll=poll,
                           priority=self.priority if heavy else "normal")

    def _log(self, r: CommandResult) -> str:
        cmd = " ".join(r.argv[1:])
        body = truncate(r.stderr.strip(), 8000)
        return self.sanitizer.text(f"$ restic {cmd}\n[exit={r.returncode} {r.duration_ms}ms]\n{body}")

    def _fail(self, r: CommandResult) -> AdapterError:
        e = classify_failure(r)
        e.details["log"] = self._log(r)
        return e

    @staticmethod
    def _snap(raw: dict[str, Any]) -> RecoveryPointInfo:
        return RecoveryPointInfo(
            native_id=raw["id"],
            created_at=parse_restic_time(raw["time"]),
            hostname=raw.get("hostname"),
            paths=list(raw.get("paths") or []),
            tags=list(raw.get("tags") or []),
            metadata={k: raw.get(k) for k in ("short_id", "tree", "parent", "username", "program_version",
                                              "summary") if raw.get(k) is not None},
        )

    # -- interface -----------------------------------------------------------------------------------------
    def tool_version(self) -> str:
        r = run_command([self._binary, "version"], timeout=15, env=self._env)  # version takes no -o options
        return r.stdout.strip() if r.ok else "unknown"

    def validate_credentials(self) -> OperationResult:
        r = self._run("cat", ["config"], timeout=60)
        if not r.ok:
            e = self._fail(r)
            return OperationResult(False, r.duration_ms, str(e), {"code": e.code}, self._log(r))
        return OperationResult(True, r.duration_ms, "repository opened and password accepted", {}, self._log(r))

    def list_recovery_points(self) -> list[RecoveryPointInfo]:
        r = self._run("snapshots", [], timeout=300)
        if not r.ok:
            raise self._fail(r)
        try:
            data = json.loads(r.stdout or "[]")
        except ValueError as exc:
            raise AdapterError("adapter_error", "could not parse restic snapshot list") from exc
        return sorted((self._snap(s) for s in data or []), key=lambda s: s.created_at)

    def get_recovery_point_metadata(self, native_id: str) -> RecoveryPointInfo:
        if not SNAPSHOT_ID_RE.match(native_id):
            raise AdapterError("invalid_argument", "invalid snapshot id")
        r = self._run("snapshots", ["--", native_id], timeout=120)
        if not r.ok:
            raise self._fail(r)
        data = json.loads(r.stdout or "[]")
        if not data:
            raise AdapterError("recovery_point_missing", "snapshot not found in repository")
        return self._snap(data[0])

    def list_dir(self, snapshot: str, path: str, limit: int = 2000) -> dict[str, Any]:
        """Direct children of `path` inside a snapshot (read-only), for picking files and folders in the UI."""
        if snapshot != "latest" and not SNAPSHOT_ID_RE.match(snapshot):
            raise AdapterError("invalid_argument", "invalid snapshot id")
        if not path.startswith("/") or ".." in path.split("/") or "\x00" in path:
            raise AdapterError("invalid_argument", "path must be absolute")
        norm = "/" + path.strip("/") if path.strip("/") else "/"
        r = self._run("ls", ["--", snapshot, norm], timeout=180)
        if not r.ok:
            raise self._fail(r)
        snap: dict[str, Any] = {}
        entries = []
        for line in r.stdout.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if "tree" in item and "paths" in item:
                snap = {"id": item.get("id"), "time": item.get("time"), "paths": item.get("paths")}
                continue
            ipath = item.get("path", "")
            parent = ipath.rsplit("/", 1)[0] or "/"
            if parent != norm or ipath == norm:
                continue
            entries.append({"name": item.get("name"), "path": ipath, "type": item.get("type"),
                            "size": item.get("size"), "mtime": item.get("mtime")})
            if len(entries) >= limit:
                break
        entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
        return {"snapshot": snap, "path": norm, "entries": entries, "truncated": len(entries) >= limit}

    def estimate_restore_size(self, native_id: str, timeout: float) -> int | None:
        if not SNAPSHOT_ID_RE.match(native_id):
            raise AdapterError("invalid_argument", "invalid snapshot id")
        r = self._run("stats", ["--mode", "restore-size", "--", native_id], timeout=min(timeout, 600))
        if not r.ok:
            return None
        try:
            return int(json.loads(r.stdout.strip().splitlines()[-1])["total_size"])
        except (ValueError, KeyError, IndexError):
            return None

    def check_repository(self, *, read_data_subset: str | None, timeout: float,
                         poll: Callable[[], None] | None = None) -> OperationResult:
        args = ["--read-data-subset", read_data_subset] if read_data_subset else []
        r = self._run("check", args, timeout=timeout, poll=poll, no_lock=False, json_out=False)
        log = self.sanitizer.text(f"$ restic check {' '.join(args)}\n[exit={r.returncode}]\n"
                                  + truncate((r.stdout + "\n" + r.stderr).strip(), 8000))
        if r.timed_out or r.aborted:
            raise self._fail(r)
        if r.returncode != 0:
            e = classify_failure(r)
            if e.code in ("auth_failed", "repository_unavailable", "repository_locked"):
                e.details["log"] = log
                raise e
            return OperationResult(False, r.duration_ms, "repository check reported errors",
                                   {"returncode": r.returncode}, log)
        return OperationResult(True, r.duration_ms, "no errors were found", {"read_data_subset": read_data_subset},
                               log)

    def restore_to_destination(self, native_id: str, destination: Path, *, include: list[str],
                               timeout: float, poll: Callable[[], None] | None = None) -> OperationResult:
        if not SNAPSHOT_ID_RE.match(native_id):
            raise AdapterError("invalid_argument", "invalid snapshot id")
        args = ["--target", str(destination), "--verify"]
        for pat in include:
            if pat.startswith("-"):
                raise AdapterError("invalid_argument", "include pattern may not start with '-'")
            args += ["--include", pat]
        args += ["--", native_id]
        r = self._run("restore", args, timeout=timeout, poll=poll)
        summary: dict[str, Any] = {}
        errors: list[str] = []
        for line in r.stdout.splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("message_type") == "summary":
                summary = msg
            elif msg.get("message_type") == "error":
                errors.append(str(msg.get("error", {}).get("message") or msg.get("item") or msg))
        if r.timed_out or (r.aborted is not None):
            raise self._fail(r)
        details = {"summary": summary, "errors": self.sanitizer.obj(errors[:50])}
        if r.returncode != 0:
            e = classify_failure(r)
            if e.code in ("auth_failed", "repository_unavailable", "repository_locked", "recovery_point_missing"):
                e.details["log"] = self._log(r)
                raise e
            return OperationResult(False, r.duration_ms, f"restore reported errors (exit {r.returncode})",
                                   details, self._log(r))
        return OperationResult(True, r.duration_ms, "restore and verification completed", details, self._log(r))


def build_adapter(adapter: str, config: dict[str, Any], secret: dict[str, Any],
                  sanitizer: Sanitizer | None = None, **opts: Any) -> BackupAdapter:
    if adapter == "restic":
        return ResticAdapter(config, secret, sanitizer, **opts)
    raise AdapterError("unsupported_adapter", f"adapter {adapter!r} is not supported")


__all__ = ["ResticAdapter", "build_adapter", "AbortRequested"]

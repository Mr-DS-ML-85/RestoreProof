"""Bounded subprocess execution.

- argv arrays only, never a shell string
- executable allowlist
- controlled environment (nothing inherited except PATH/HOME/locale)
- wall-clock timeout, cancellation hook, and process-group termination
- capped output capture
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from restoreproof.config import get_settings

MAX_CAPTURE = 2 * 1024 * 1024


class CommandNotAllowed(Exception):
    pass


class AbortRequested(Exception):
    """Raised by a poll hook to stop the running process (cancellation, budget exceeded)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    aborted: AbortRequested | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.aborted is None


def _base_env() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    for passthrough in ("DOCKER_HOST", "DOCKER_CONFIG", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
        if passthrough in os.environ:
            env[passthrough] = os.environ[passthrough]
    return env


def low_priority(argv: list[str]) -> list[str]:
    """Lowest CPU priority and the idle I/O class, so a restore only uses disk time production is not using.
    Wrappers are only added if present on the host; the wrapped executable was already allowlisted."""
    out = list(argv)
    if shutil.which("ionice"):
        out = ["ionice", "-c", "3", *out]
    if shutil.which("nice"):
        out = ["nice", "-n", "19", *out]
    return out


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def run_command(
    argv: Sequence[str],
    *,
    timeout: float,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    poll: Callable[[], None] | None = None,
    poll_interval: float = 1.0,
    stdin_data: bytes | None = None,
    priority: str = "normal",
) -> CommandResult:
    argv = [str(a) for a in argv]
    if not argv or argv[0] not in get_settings().allowed_executables:
        raise CommandNotAllowed(f"executable not in allowlist: {argv[:1]}")
    if priority == "low":
        argv = low_priority(argv)
    if timeout <= 0:
        return CommandResult(argv, None, "", "time budget exhausted before start", 0, timed_out=True)
    full_env = _base_env()
    full_env.update(env or {})
    start = time.monotonic()
    # Spool output to anonymous temp files so a chatty process cannot dead-lock on a full pipe.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env=full_env,
            cwd=cwd,
            start_new_session=True,  # own process group so we can kill the whole tree
        )
        if stdin_data is not None and proc.stdin:
            try:
                proc.stdin.write(stdin_data)
                proc.stdin.close()
            except BrokenPipeError:
                pass
        timed_out = False
        aborted: AbortRequested | None = None
        next_poll = start + poll_interval
        while True:
            try:
                proc.wait(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                pass
            now = time.monotonic()
            if now - start > timeout:
                timed_out = True
                _kill_group(proc)
                break
            if poll and now >= next_poll:
                next_poll = now + poll_interval
                try:
                    poll()
                except AbortRequested as exc:
                    aborted = exc
                    _kill_group(proc)
                    break
        out.seek(0)
        err.seek(0)
        stdout = out.read(MAX_CAPTURE).decode("utf-8", "replace")
        stderr = err.read(MAX_CAPTURE).decode("utf-8", "replace")
    return CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=int((time.monotonic() - start) * 1000),
        timed_out=timed_out,
        aborted=aborted,
    )

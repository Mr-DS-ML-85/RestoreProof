"""Disposable, isolated container environment for one attempt.

Isolation defaults (PRD §9):
- one `--internal` bridge network per attempt: no route to the internet or other networks
- no published ports, no host networking, no privileged mode, never the Docker socket
- `--cap-drop ALL` plus a small allowlisted set, `no-new-privileges`, CPU/memory/PID limits
- every object carries `io.restoreproof.managed=true` and the attempt id; nothing without those labels is
  ever removed
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from restoreproof.config import get_settings
from restoreproof.evidence.sanitization import Sanitizer, truncate
from restoreproof.security.process import CommandResult, run_command

LABEL_MANAGED = "io.restoreproof.managed"
LABEL_ATTEMPT = "io.restoreproof.attempt"
ALLOWED_CAPS = frozenset({"CHOWN", "SETUID", "SETGID", "FOWNER", "DAC_OVERRIDE", "NET_BIND_SERVICE", "KILL"})
DEFAULT_CAPS = ("CHOWN", "SETUID", "SETGID", "FOWNER", "DAC_OVERRIDE", "NET_BIND_SERVICE")
FORBIDDEN_MOUNT_SOURCES = ("/var/run/docker.sock", "/run/docker.sock")


class DockerError(Exception):
    def __init__(self, code: str, message: str, log: str = ""):
        super().__init__(message)
        self.code = code
        self.log = log


@dataclass(frozen=True)
class BindMount:
    source: Path
    target: str
    read_only: bool = True


def docker_available(timeout: float = 10) -> tuple[bool, str]:
    try:
        r = run_command([get_settings().docker_binary, "version", "--format", "{{.Server.Version}}"],
                        timeout=timeout)
    except FileNotFoundError:
        return False, "docker CLI not found"
    return (r.ok, r.stdout.strip() if r.ok else truncate(r.stderr.strip(), 500))


class DockerEnvironment:
    def __init__(self, attempt_id: str, run_dir: Path, register: Callable[[str, str], None],
                 sanitizer: Sanitizer):
        self.attempt_id = attempt_id
        self.short = attempt_id.split("-")[0]
        self.run_dir = run_dir.resolve()
        self.network = f"rp-{self.short}-net"
        self._register = register
        self.sanitizer = sanitizer
        self._bin = get_settings().docker_binary
        self.log: list[str] = []
        self._probe: str | None = None
        # time.monotonic() value after which no new docker command may run (the attempt's overall deadline).
        self.deadline: float | None = None

    # -- helpers -------------------------------------------------------------------------------------------
    def _docker(self, args: list[str], timeout: float, stdin: bytes | None = None,
                env: dict[str, str] | None = None) -> CommandResult:
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
        r = run_command([self._bin, *args], timeout=timeout, stdin_data=stdin, env=env)
        shown = " ".join(a if len(a) < 200 else a[:200] + "…" for a in args)
        self.log.append(self.sanitizer.text(f"$ docker {shown}\n[exit={r.returncode} {r.duration_ms}ms]"
                                            + (f"\n{truncate(r.stderr.strip(), 2000)}" if r.stderr.strip() else "")))
        return r

    def _labels(self) -> list[str]:
        return ["--label", f"{LABEL_MANAGED}=true", "--label", f"{LABEL_ATTEMPT}={self.attempt_id}"]

    def container_name(self, resource: str) -> str:
        return f"rp-{self.short}-{resource}"

    def _check_mount(self, m: BindMount) -> None:
        src = m.source.resolve()
        if str(src) in FORBIDDEN_MOUNT_SOURCES or src.is_socket():
            raise DockerError("unsafe_mount", "refusing to mount a socket into a test container")
        if src != self.run_dir and self.run_dir not in src.parents:
            raise DockerError("unsafe_mount", "only paths inside the attempt's restore directory can be mounted")

    # -- lifecycle -----------------------------------------------------------------------------------------
    def create_network(self) -> None:
        # Record the resource before creating it, so a crash between the two still leaves a cleanup record.
        self._register("network", self.network)
        r = self._docker(["network", "create", "--internal", "--driver", "bridge", *self._labels(), self.network],
                         timeout=60)
        if not r.ok:
            raise DockerError("network_create_failed", "could not create isolated test network", r.stderr)

    def pull_if_missing(self, image: str, timeout: float) -> None:
        r = self._docker(["image", "inspect", "--format", "{{.Id}}", image], timeout=30)
        if r.ok:
            return
        r = self._docker(["pull", "--quiet", image], timeout=timeout)
        if not r.ok:
            raise DockerError("image_unavailable", f"image {image} could not be pulled", r.stderr)

    def run(self, resource: str, image: str, *, env: dict[str, str] | None = None,
            mounts: list[BindMount] = (), memory_mb: int = 512, cpus: float = 1.0, pids: int = 256,
            cap_add: tuple[str, ...] = DEFAULT_CAPS, command: list[str] | None = None, user: str | None = None,
            read_only_rootfs: bool = False, entrypoint: str | None = None, timeout: float = 120,
            cpu_shares: int = 256, io_weight: int | None = None) -> str:
        name = self.container_name(resource)
        caps = [c for c in cap_add if c in ALLOWED_CAPS]
        args = ["run", "--detach", "--name", name, "--network", self.network, "--network-alias", resource,
                "--hostname", resource, *self._labels(),
                "--memory", f"{memory_mb}m", "--memory-swap", f"{memory_mb}m", "--cpus", str(cpus),
                "--pids-limit", str(pids), "--cpu-shares", str(cpu_shares), "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "--restart", "no", "--log-driver", "json-file", "--log-opt", "max-size=5m"]
        if io_weight:
            args += ["--blkio-weight", str(io_weight)]
        for c in caps:
            args += ["--cap-add", c]
        if read_only_rootfs:
            args += ["--read-only", "--tmpfs", "/tmp:rw,size=64m", "--tmpfs", "/run:rw,size=16m"]
        if user:
            args += ["--user", user]
        for k, v in (env or {}).items():
            args += ["--env", f"{k}={v}"]
        for m in mounts:
            self._check_mount(m)
            spec = f"type=bind,source={m.source.resolve()},target={m.target}"
            args += ["--mount", spec + (",readonly" if m.read_only else "")]
        if entrypoint:
            args += ["--entrypoint", entrypoint]
        args += ["--", image, *(command or [])]
        self._register("container", name)
        r = self._docker(args, timeout=timeout)
        if not r.ok:
            raise DockerError("container_start_failed", f"container {resource} failed to start", r.stderr)
        return name

    def exec(self, container: str, argv: list[str], *, timeout: float, stdin: bytes | None = None,
             env: dict[str, str] | None = None, user: str | None = None) -> CommandResult:
        args = ["exec"]
        if stdin is not None:
            args.append("--interactive")
        if user:
            args += ["--user", user]
        for k, v in (env or {}).items():
            args += ["--env", f"{k}={v}"]
        return self._docker([*args, container, *argv], timeout=timeout, stdin=stdin)

    def state(self, container: str) -> dict:
        r = self._docker(["inspect", "--format", "{{json .State}}", container], timeout=30)
        if not r.ok:
            return {}
        try:
            return json.loads(r.stdout)
        except ValueError:
            return {}

    def logs_tail(self, container: str, lines: int = 80) -> str:
        r = run_command([self._bin, "logs", "--tail", str(lines), container], timeout=30)
        return self.sanitizer.text(truncate((r.stdout + r.stderr).strip(), 6000))

    def wait_running(self, container: str, timeout: float) -> tuple[bool, str]:
        """Running, and healthy if the image defines a HEALTHCHECK."""
        deadline = time.monotonic() + timeout
        last = "unknown"
        while time.monotonic() < deadline:
            st = self.state(container)
            if not st:
                last = "container not found"
            elif st.get("Status") in ("exited", "dead"):
                return False, f"container exited with code {st.get('ExitCode')}"
            elif st.get("Running"):
                health = (st.get("Health") or {}).get("Status")
                if health in (None, "healthy"):
                    return True, "running" + (" and healthy" if health else "")
                if health == "unhealthy":
                    return False, "container reported unhealthy"
                last = f"health: {health}"
            time.sleep(1)
        return False, f"not ready within {int(timeout)}s ({last})"

    def http_probe(self, url: str, *, method: str, timeout: int) -> tuple[int | None, str, str]:
        """Issue an HTTP request from inside the isolated network. Returns (status, body_snippet, error)."""
        if self._probe is None:
            image = get_settings().http_probe_image
            self.pull_if_missing(image, timeout=300)
            self._probe = self.run("probe", image, entrypoint="sleep", command=["86400"], memory_mb=64,
                                   cpus=0.5, pids=32, cap_add=(), read_only_rootfs=True)
        argv = ["curl", "--silent", "--show-error", "--max-time", str(timeout), "--max-filesize", "1048576",
                "--output", "-", "--write-out", "\n__RP_STATUS__%{http_code}", "--request", method]
        if method == "HEAD":
            argv.append("--head")
        argv += ["--", url]
        r = self.exec(self._probe, argv, timeout=timeout + 15)
        out = r.stdout
        marker = out.rfind("\n__RP_STATUS__")
        if marker < 0:
            return None, "", truncate(r.stderr.strip() or "no response", 500)
        code = out[marker + len("\n__RP_STATUS__"):].strip()
        body = out[:marker]
        status = int(code) if code.isdigit() and code != "000" else None
        return status, body[:65536], "" if status else truncate(r.stderr.strip() or "connection failed", 500)


# -- cleanup primitives (used by the resource tracker, also for orphans after a crash) ------------------------
def _owned(kind: str, name: str) -> tuple[bool | None, str]:
    """True if the object exists and carries our label, False if it exists without it, None if absent."""
    fmt = "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"
    sub = ["inspect"] if kind == "container" else ["network", "inspect"]
    r = run_command([get_settings().docker_binary, *sub, "--format", fmt, "--", name], timeout=30)
    if not r.ok:
        if "no such" in r.stderr.lower() or "not found" in r.stderr.lower():
            return None, ""
        return False, truncate(r.stderr.strip(), 300)
    try:
        labels = json.loads(r.stdout) or {}
    except ValueError:
        labels = {}
    return labels.get(LABEL_MANAGED) == "true", ""


def remove_container(name: str) -> None:
    owned, err = _owned("container", name)
    if owned is None:
        return
    if not owned:
        raise DockerError("ownership_check_failed", f"container {name} is not labelled as RestoreProof-managed "
                                                    f"{err}".strip())
    r = run_command([get_settings().docker_binary, "rm", "--force", "--volumes", "--", name], timeout=120)
    if not r.ok and "no such" not in r.stderr.lower():
        raise DockerError("container_remove_failed", truncate(r.stderr.strip(), 500))


def remove_network(name: str) -> None:
    owned, err = _owned("network", name)
    if owned is None:
        return
    if not owned:
        raise DockerError("ownership_check_failed", f"network {name} is not RestoreProof-managed {err}".strip())
    r = run_command([get_settings().docker_binary, "network", "rm", "--", name], timeout=60)
    if not r.ok and "not found" not in r.stderr.lower():
        raise DockerError("network_remove_failed", truncate(r.stderr.strip(), 500))


def list_managed(kind: str) -> list[tuple[str, str]]:
    """[(name, attempt_id)] for every labelled container/network on this host."""
    b = get_settings().docker_binary
    fmt = '{{.Names}}\t{{.Label "' + LABEL_ATTEMPT + '"}}' if kind == "container" else \
        '{{.Name}}\t{{.Label "' + LABEL_ATTEMPT + '"}}'
    args = ["ps", "--all"] if kind == "container" else ["network", "ls"]
    r = run_command([b, *args, "--filter", f"label={LABEL_MANAGED}=true", "--format", fmt], timeout=60)
    if not r.ok:
        return []
    return [tuple(line.split("\t", 1)) for line in r.stdout.splitlines() if "\t" in line]  # type: ignore[misc]

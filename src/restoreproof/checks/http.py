"""Temporary application services and HTTP assertions, all inside the attempt's internal network."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from restoreproof.definitions import ServiceResource
from restoreproof.jobs.state_machine import CheckStatus as S
from restoreproof.runner.docker import BindMount, DockerEnvironment, DockerError
from restoreproof.security.paths import UnsafePath, resolve_within


@dataclass
class ServiceInstance:
    spec: ServiceResource
    container: str | None
    ready: bool = False


def start(env: DockerEnvironment, spec: ServiceResource, restore_base: Path) -> tuple[ServiceInstance, tuple]:
    try:
        mounts = []
        for m in spec.mounts:
            src = resolve_within(restore_base, m.from_)
            if not src.exists():
                return ServiceInstance(spec, None), (S.FAILED, f"mount source {m.from_} missing from restore", {})
            mounts.append(BindMount(src, m.to, m.readOnly))
    except UnsafePath as exc:
        return ServiceInstance(spec, None), (S.FAILED, f"unsafe mount rejected: {exc}", {})
    try:
        env.pull_if_missing(spec.image, timeout=900)
        name = env.run(spec.name, spec.image, env=spec.env, mounts=mounts, memory_mb=spec.limits.memoryMb,
                       cpus=spec.limits.cpus, pids=spec.limits.pidsLimit,
                       cpu_shares=spec.limits.cpuShares, io_weight=spec.limits.ioWeight, cap_add=tuple(spec.capAdd),
                       command=spec.command, user=spec.user, read_only_rootfs=spec.readOnlyRootfs)
    except DockerError as exc:
        return ServiceInstance(spec, None), (S.ERROR, str(exc), {"code": exc.code,
                                                                 "log": env.sanitizer.text(exc.log)[:2000]})
    inst = ServiceInstance(spec, name)
    t0 = time.monotonic()
    ok, msg = env.wait_running(name, spec.readyTimeoutSeconds)
    if ok and spec.readinessPath:
        deadline = t0 + spec.readyTimeoutSeconds
        ok, msg = False, "readiness endpoint never answered"
        while time.monotonic() < deadline:
            status, _body, err = env.http_probe(f"http://{spec.name}:{spec.port}{spec.readinessPath}",
                                                method="GET", timeout=5)
            if status is not None and status < 500:
                ok, msg = True, f"readiness endpoint answered {status}"
                break
            msg = err or f"readiness endpoint answered {status}"
            if not env.wait_running(name, 1)[0]:
                msg = "container stopped while waiting for readiness"
                break
            time.sleep(1)
    inst.ready = ok
    details = {"ready_ms": int((time.monotonic() - t0) * 1000), "image": spec.image}
    if not ok:
        details["container_log"] = env.logs_tail(name)
    return inst, ((S.PASSED if ok else S.FAILED), msg, details)


def run_check(check, env: DockerEnvironment, inst: ServiceInstance | None) -> tuple[str, str, dict]:
    if inst is None or inst.container is None:
        return S.SKIPPED, "service was not started", {}
    if not inst.ready:
        return S.SKIPPED, "service never became ready", {}
    url = f"http://{inst.spec.name}:{inst.spec.port}{check.path}"
    t0 = time.monotonic()
    status, body, err = env.http_probe(url, method=check.method, timeout=check.timeoutSeconds)
    details = {"url_path": check.path, "status": status, "elapsed_ms": int((time.monotonic() - t0) * 1000)}
    if status is None:
        return S.FAILED, f"no HTTP response: {err}", details
    if status != check.expectedStatus:
        details["body_excerpt"] = env.sanitizer.text(body[:500])
        return S.FAILED, f"HTTP {status}, expected {check.expectedStatus}", details
    if check.bodyContains is not None and check.bodyContains not in body:
        return S.FAILED, f"response did not contain {check.bodyContains!r}", details
    return S.PASSED, f"HTTP {status}" + (" with expected content" if check.bodyContains else ""), details

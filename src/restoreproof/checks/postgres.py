"""Disposable PostgreSQL: start, wait for readiness, import, then run read-only assertions as a
least-privilege role. All SQL runs via `docker exec` inside the isolated network; no port is published."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from restoreproof.checks.base import compare
from restoreproof.definitions import PostgresResource
from restoreproof.evidence.sanitization import truncate
from restoreproof.jobs.state_machine import CheckStatus as S
from restoreproof.runner.docker import BindMount, DockerEnvironment, DockerError
from restoreproof.security.paths import UnsafePath, resolve_within

VERIFIER = "rp_verifier"


@dataclass
class PostgresInstance:
    spec: PostgresResource
    container: str
    server_version: str = ""
    ready: bool = False
    imported: bool = False


def _psql(env: DockerEnvironment, inst: PostgresInstance, sql: str, *, user: str = "postgres",
          timeout: float = 60, read_only: bool = False) -> tuple[bool, str, str]:
    opts = "-c statement_timeout=%d" % int(timeout * 1000)
    if read_only:
        opts += " -c default_transaction_read_only=on"
    r = env.exec(inst.container,
                 ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", inst.spec.database,
                  "-c", sql], timeout=timeout + 15, env={"PGOPTIONS": opts})
    return r.ok, r.stdout.strip(), env.sanitizer.text(truncate(r.stderr.strip(), 2000))


def resolve_dump(restore_base: Path, pattern: str) -> tuple[Path | None, int]:
    """Exact path, or a glob (e.g. Immich's timestamped backups): the newest match wins (mtime, then name)."""
    if not any(ch in pattern for ch in "*?["):
        p = resolve_within(restore_base, pattern)
        return (p if p.is_file() else None), 1
    root = restore_base.resolve()
    validate = resolve_within  # every match is re-checked for traversal / symlinks
    matches = []
    for m in root.glob(pattern):
        try:
            rp = validate(root, m.relative_to(root).as_posix())
        except UnsafePath:
            continue
        if rp.is_file():
            matches.append(rp)
    if not matches:
        return None, 0
    matches.sort(key=lambda p: (p.stat().st_mtime, p.name))
    return matches[-1], len(matches)


def start(env: DockerEnvironment, spec: PostgresResource, restore_base: Path) -> tuple[PostgresInstance | None,
                                                                                   list[tuple[str, str, str, dict]]]:
    """Returns the instance and a list of (name, status, message, details) lifecycle check records."""
    records: list[tuple[str, str, str, dict]] = []
    try:
        dump, candidates = resolve_dump(restore_base, spec.dumpPath)
    except UnsafePath as exc:
        records.append((f"postgres_dump_present:{spec.name}", S.FAILED, str(exc), {}))
        return None, records
    if dump is None:
        records.append((f"postgres_dump_present:{spec.name}", S.FAILED,
                        f"dump {spec.dumpPath} was not found in the restored data",
                        {} if any(ch in spec.dumpPath for ch in "*?[") else {"missing_path": spec.dumpPath}))
        return None, records
    rel = dump.relative_to(restore_base.resolve()).as_posix()
    records.append((f"postgres_dump_present:{spec.name}", S.PASSED,
                    f"dump {rel} found ({dump.stat().st_size} bytes)"
                    + (f", newest of {candidates} matches" if candidates > 1 else ""),
                    {"size": dump.stat().st_size, "file": rel, "matches": candidates}))

    image = spec.effective_image
    password = secrets.token_urlsafe(24)
    env.sanitizer.add(password)
    try:
        env.pull_if_missing(image, timeout=900)
        name = env.run(spec.name, image, env={"POSTGRES_PASSWORD": password, "POSTGRES_DB": spec.database},
                       mounts=[BindMount(dump, "/rp-input/dump", True)], memory_mb=spec.limits.memoryMb,
                       cpus=spec.limits.cpus, pids=spec.limits.pidsLimit,
                       cpu_shares=spec.limits.cpuShares, io_weight=spec.limits.ioWeight)
    except DockerError as exc:
        records.append((f"postgres_started:{spec.name}", S.ERROR, str(exc), {"code": exc.code,
                                                                             "log": env.sanitizer.text(exc.log)}))
        return None, records
    inst = PostgresInstance(spec, name)

    # The image's init phase runs a temporary server on the unix socket only; checking TCP on 127.0.0.1
    # waits for the real server.
    deadline = time.monotonic() + spec.readyTimeoutSeconds
    start_t = time.monotonic()
    while time.monotonic() < deadline:
        r = env.exec(name, ["pg_isready", "-q", "-h", "127.0.0.1", "-U", "postgres", "-d", spec.database],
                     timeout=20)
        if r.ok:
            inst.ready = True
            break
        st = env.state(name)
        if st and st.get("Status") in ("exited", "dead"):
            break
        time.sleep(1)
    if not inst.ready:
        records.append((f"postgres_ready:{spec.name}", S.FAILED,
                        f"database did not become ready within {spec.readyTimeoutSeconds}s",
                        {"container_log": env.logs_tail(name)}))
        return inst, records
    ok, ver, _ = _psql(env, inst, "SHOW server_version")
    inst.server_version = ver
    records.append((f"postgres_ready:{spec.name}", S.PASSED, f"PostgreSQL {ver} accepting connections",
                    {"server_version": ver, "ready_ms": int((time.monotonic() - start_t) * 1000)}))

    for role in spec.createRoles:
        _psql(env, inst, f'DO $$BEGIN CREATE ROLE "{role}" NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END$$')

    t0 = time.monotonic()
    stop = spec.onImportError == "stop"
    if spec.format == "plain":
        tool = ["psql", "-X", "-q", *(["-v", "ON_ERROR_STOP=1"] if stop else []), "-U", "postgres",
                "-d", spec.database]
        argv = [*tool, "-f", "/rp-input/dump"]
    else:
        tool = ["pg_restore", *(["--exit-on-error"] if stop else []), "--no-owner", "--no-privileges",
                "-U", "postgres", "-d", spec.database]
        argv = [*tool, "/rp-input/dump"]
    if spec.compression == "gzip":
        # Fixed pipeline; the only interpolated value is the database name, which the schema restricts to
        # [a-z_][a-z0-9_]*, so no user-controlled text reaches the shell.
        # POSIX sh only (Debian images use dash, which has no `pipefail`): verify the whole archive first, so
        # a truncated .gz is reported instead of being silently half-imported.
        argv = ["sh", "-c", "gunzip -t /rp-input/dump && gunzip -c /rp-input/dump | " + " ".join(tool)]
    r = env.exec(name, argv, timeout=spec.importTimeoutSeconds)
    stderr = env.sanitizer.text(r.stderr)
    errors = [ln for ln in stderr.splitlines() if re.search(r"\bERROR\b|error:", ln)]
    import_ms = int((time.monotonic() - t0) * 1000)
    details: dict[str, Any] = {"duration_ms": import_ms, "error_count": len(errors), "errors": errors[:20],
                               "format": spec.format}
    if r.timed_out:
        records.append((f"postgres_import:{spec.name}", S.FAILED,
                        f"import exceeded {spec.importTimeoutSeconds}s", details))
        return inst, records
    if not r.ok or (errors and spec.onImportError == "stop"):
        records.append((f"postgres_import:{spec.name}", S.FAILED,
                        f"import failed: {errors[0] if errors else 'exit ' + str(r.returncode)}"[:400], details))
        return inst, records
    inst.imported = True
    msg = "dump imported" + (f" with {len(errors)} reported errors (onImportError=continue)" if errors else "")
    records.append((f"postgres_import:{spec.name}", S.PASSED, msg, details))

    # Least-privilege verification role: can read everything, can write nothing.
    major = int(re.match(r"\d+", ver).group()) if re.match(r"\d+", ver) else 0
    grant = (f"GRANT pg_read_all_data TO {VERIFIER}" if major >= 14 else
             f"GRANT USAGE ON SCHEMA public TO {VERIFIER}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {VERIFIER}")
    ok, _, err = _psql(env, inst, f"DO $$BEGIN CREATE ROLE {VERIFIER} LOGIN; EXCEPTION WHEN duplicate_object "
                                  f"THEN NULL; END$$; {grant}")
    if not ok:
        records.append((f"postgres_verifier_role:{spec.name}", S.ERROR, f"could not create verifier role: {err}", {}))
    return inst, records


def _coerce(raw: str, expected: Any) -> Any:
    """Interpret psql's text output in the type the assertion expects (so '20261001' stays a string when a
    string is expected, and becomes a number when a number is expected)."""
    value = (raw.splitlines()[0] if raw else "").split("|")[0]
    if isinstance(expected, bool):
        return {"t": True, "f": False}.get(value, value)
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value
    if isinstance(expected, str):
        return value
    return _scalar(raw)


def _scalar(raw: str) -> Any:
    first = raw.splitlines()[0] if raw else ""
    value = first.split("|")[0]
    if value == "t":
        return True
    if value == "f":
        return False
    if value == "":
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


def run_check(check: Any, env: DockerEnvironment, inst: PostgresInstance | None) -> tuple[str, str, dict]:
    if inst is None or not inst.ready:
        return S.SKIPPED, "database is not available (see readiness/import results)", {}
    if not inst.imported:
        return S.SKIPPED, "database import did not succeed", {}
    if check.type == "postgres_table_exists":
        sql = f"SELECT to_regclass('{check.table}') IS NOT NULL"
        expect, op = True, "eq"
    elif check.type == "postgres_row_count":
        if _scalar(_psql(env, inst, f"SELECT to_regclass('{check.table}') IS NOT NULL", user=VERIFIER,
                         read_only=True)[1]) is not True:
            return S.FAILED, f"table {check.table} does not exist", {}
        sql = f"SELECT count(*) FROM {check.table}"
        expect, op = None, "eq"
    else:
        sql, expect, op = check.query, check.expect, check.op
    ok, out, err = _psql(env, inst, sql, user=VERIFIER, read_only=True)
    if not ok:
        # A query error against the restored data (e.g. missing column) is a failed assertion, not an
        # infrastructure error: the restored database does not satisfy the stated invariant.
        return S.FAILED, f"query error: {err.splitlines()[0] if err else 'unknown'}"[:400], {"query": sql}
    actual = _scalar(out) if check.type == "postgres_row_count" else _coerce(out, expect)
    details = {"query": sql, "actual": actual}
    if check.type == "postgres_row_count":
        lo, hi = check.min, check.max
        if lo is not None and actual < lo:
            return S.FAILED, f"{actual} rows, expected at least {lo}", details
        if hi is not None and actual > hi:
            return S.FAILED, f"{actual} rows, expected at most {hi}", details
        return S.PASSED, f"{actual} rows", details
    details["expected"], details["op"] = expect, op
    if compare(actual, expect, op):
        return S.PASSED, f"result {actual!r} {op} {expect!r}", details
    return S.FAILED, f"result {actual!r} does not satisfy {op} {expect!r}", details

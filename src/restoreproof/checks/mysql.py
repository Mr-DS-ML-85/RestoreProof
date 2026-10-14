"""Disposable MariaDB/MySQL: start, wait for the real server (TCP, not the init-time socket server), import
the dump, then run assertions as a SELECT-only user in a read-only session. Everything runs via
`docker exec` on the attempt's internal network; passwords travel as MYSQL_PWD environment variables."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from restoreproof.checks.base import compare
from restoreproof.checks.postgres import resolve_dump
from restoreproof.definitions import MariaDBResource
from restoreproof.evidence.sanitization import truncate
from restoreproof.jobs.state_machine import CheckStatus as S
from restoreproof.runner.docker import BindMount, DockerEnvironment, DockerError
from restoreproof.security.paths import UnsafePath

VERIFIER = "rp_verifier"


@dataclass
class MysqlInstance:
    spec: MariaDBResource
    container: str
    root_pw: str
    verifier_pw: str
    client: str
    admin: str
    server_version: str = ""
    ready: bool = False
    imported: bool = False


def _sql(env: DockerEnvironment, inst: MysqlInstance, sql: str, *, user: str = "root", timeout: float = 60,
         database: bool = True) -> tuple[bool, str, str]:
    pw = inst.root_pw if user == "root" else inst.verifier_pw
    argv = [inst.client, "-N", "-B", "-h", "127.0.0.1", "-u", user]
    if database:
        argv += ["-D", inst.spec.database]
    r = env.exec(inst.container, [*argv, "-e", sql], timeout=timeout + 15, env={"MYSQL_PWD": pw})
    return r.ok, r.stdout.strip(), env.sanitizer.text(truncate(r.stderr.strip(), 2000))


def start(env: DockerEnvironment, spec: MariaDBResource, restore_base: Path) -> tuple[MysqlInstance | None, list]:
    records: list[tuple[str, str, str, dict]] = []
    label = f"{spec.engine}"
    try:
        dump, matches = resolve_dump(restore_base, spec.dumpPath)
    except UnsafePath as exc:
        records.append((f"{label}_dump_present:{spec.name}", S.FAILED, str(exc), {}))
        return None, records
    if dump is None:
        records.append((f"{label}_dump_present:{spec.name}", S.FAILED,
                        f"dump {spec.dumpPath} was not found in the restored data",
                        {} if any(ch in spec.dumpPath for ch in "*?[") else {"missing_path": spec.dumpPath}))
        return None, records
    records.append((f"{label}_dump_present:{spec.name}", S.PASSED, f"dump found ({dump.stat().st_size} bytes)",
                    {"size": dump.stat().st_size, "matches": matches}))
    root_pw, ver_pw = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    env.sanitizer.add(root_pw, ver_pw)
    mariadb = spec.engine == "mariadb"
    client, admin = ("mariadb", "mariadb-admin") if mariadb else ("mysql", "mysqladmin")
    envs = ({"MARIADB_ROOT_PASSWORD": root_pw, "MARIADB_DATABASE": spec.database} if mariadb else
            {"MYSQL_ROOT_PASSWORD": root_pw, "MYSQL_DATABASE": spec.database})
    try:
        env.pull_if_missing(spec.effective_image, timeout=900)
        name = env.run(spec.name, spec.effective_image, env=envs, mounts=[BindMount(dump, "/rp-input/dump", True)],
                       memory_mb=max(spec.limits.memoryMb, 384), cpus=spec.limits.cpus, pids=spec.limits.pidsLimit,
                       cpu_shares=spec.limits.cpuShares, io_weight=spec.limits.ioWeight)
    except DockerError as exc:
        records.append((f"{label}_started:{spec.name}", S.ERROR, str(exc), {"code": exc.code}))
        return None, records
    inst = MysqlInstance(spec, name, root_pw, ver_pw, client, admin)
    t0 = time.monotonic()
    deadline = t0 + spec.readyTimeoutSeconds
    while time.monotonic() < deadline:
        # The image's init phase runs a server without networking; TCP answers only once the real one is up.
        r = env.exec(name, [admin, "ping", "-h", "127.0.0.1", "-u", "root", "--silent"], timeout=20,
                     env={"MYSQL_PWD": root_pw})
        if r.ok:
            ok, ver, _ = _sql(env, inst, "SELECT VERSION()", database=False)
            if ok:
                inst.ready, inst.server_version = True, ver
                break
        st = env.state(name)
        if st and st.get("Status") in ("exited", "dead"):
            break
        time.sleep(2)
    if not inst.ready:
        records.append((f"{label}_ready:{spec.name}", S.FAILED,
                        f"database did not become ready within {spec.readyTimeoutSeconds}s",
                        {"container_log": env.logs_tail(name)}))
        return inst, records
    records.append((f"{label}_ready:{spec.name}", S.PASSED, f"{spec.engine} {inst.server_version} accepting connections",
                    {"server_version": inst.server_version, "ready_ms": int((time.monotonic() - t0) * 1000)}))
    force = "" if spec.onImportError == "stop" else " --force"
    src = "gunzip -c /rp-input/dump" if spec.compression == "gzip" else "cat /rp-input/dump"
    check = "gunzip -t /rp-input/dump && " if spec.compression == "gzip" else ""
    # Fixed pipeline; the database name is restricted to [A-Za-z_][A-Za-z0-9_]* by the schema.
    cmd = f"{check}{src} | {client}{force} -h 127.0.0.1 -u root {spec.database}"
    t1 = time.monotonic()
    r = env.exec(name, ["sh", "-c", cmd], timeout=spec.importTimeoutSeconds, env={"MYSQL_PWD": root_pw})
    errors = [ln for ln in env.sanitizer.text(r.stderr).splitlines() if "ERROR" in ln]
    details: dict[str, Any] = {"duration_ms": int((time.monotonic() - t1) * 1000), "error_count": len(errors),
                               "errors": errors[:20]}
    if r.timed_out or not r.ok or (errors and spec.onImportError == "stop"):
        records.append((f"{label}_import:{spec.name}", S.FAILED,
                        f"import failed: {errors[0] if errors else 'exit ' + str(r.returncode)}"[:400], details))
        return inst, records
    inst.imported = True
    records.append((f"{label}_import:{spec.name}", S.PASSED, "dump imported", details))
    host = "'%'"
    ok, _, err = _sql(env, inst, f"CREATE USER IF NOT EXISTS '{VERIFIER}'@{host} IDENTIFIED BY '{ver_pw}'; "
                                 f"GRANT SELECT ON `{spec.database}`.* TO '{VERIFIER}'@{host}; FLUSH PRIVILEGES;",
                      database=False)
    if not ok:
        records.append((f"{label}_verifier_role:{spec.name}", S.ERROR, f"could not create read-only user: {err}", {}))
    return inst, records


def _first(raw: str) -> str:
    return raw.splitlines()[0].split("\t")[0] if raw else ""


def _coerce(raw: str, expected: Any) -> Any:
    v = _first(raw)
    if v == "NULL":
        return None
    if isinstance(expected, bool):
        return {"1": True, "0": False}.get(v, v)
    if isinstance(expected, (int, float)):
        try:
            return int(v)
        except ValueError:
            try:
                return float(v)
            except ValueError:
                return v
    return v


def run_check(check: Any, env: DockerEnvironment, inst: MysqlInstance | None) -> tuple[str, str, dict]:
    if inst is None or not inst.ready:
        return S.SKIPPED, "database is not available (see readiness/import results)", {}
    if not inst.imported:
        return S.SKIPPED, "database import did not succeed", {}
    ro = "SET SESSION TRANSACTION READ ONLY; "
    if check.type == "mysql_table_exists":
        sql = ("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() "
               f"AND table_name = '{check.table}'")
        ok, out, err = _sql(env, inst, ro + sql, user=VERIFIER)
        if not ok:
            return S.FAILED, f"query error: {err.splitlines()[0] if err else 'unknown'}"[:400], {}
        exists = _first(out) == "1"
        return (S.PASSED, f"table {check.table} exists", {}) if exists else \
            (S.FAILED, f"table {check.table} does not exist", {"database": inst.spec.database})
    if check.type == "mysql_row_count":
        ok, out, err = _sql(env, inst, ro + f"SELECT COUNT(*) FROM `{check.table}`", user=VERIFIER)
        if not ok:
            return S.FAILED, f"query error: {err.splitlines()[0] if err else 'unknown'}"[:400], {}
        n = int(_first(out) or 0)
        if check.min is not None and n < check.min:
            return S.FAILED, f"{n} rows, expected at least {check.min}", {"actual": n}
        if check.max is not None and n > check.max:
            return S.FAILED, f"{n} rows, expected at most {check.max}", {"actual": n}
        return S.PASSED, f"{n} rows", {"actual": n}
    ok, out, err = _sql(env, inst, ro + check.query, user=VERIFIER)
    if not ok:
        return S.FAILED, f"query error: {err.splitlines()[0] if err else 'unknown'}"[:400], {"query": check.query}
    actual = _coerce(out, check.expect)
    details = {"query": check.query, "actual": actual, "expected": check.expect, "op": check.op}
    if compare(actual, check.expect, check.op):
        return S.PASSED, f"result {actual!r} {check.op} {check.expect!r}", details
    return S.FAILED, f"result {actual!r} does not satisfy {check.op} {check.expect!r}", details


__all__ = ["start", "run_check", "MysqlInstance"]

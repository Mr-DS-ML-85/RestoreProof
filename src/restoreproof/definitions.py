"""RecoveryTest definition schema (apiVersion restoreproof.io/v1alpha1).

Everything is strict: unknown keys are rejected, paths are relative and traversal-free, every check `target`
must name a resource declared in `spec.resources`, and there is no field that accepts a shell command.
"""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Any, Literal, Union

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    ValidationError,
    field_validator,
    model_validator,
)

from restoreproof.security.paths import UnsafePath, validate_relative

MAX_DEFINITION_BYTES = 128 * 1024
NAME_RE = r"^[a-z][a-z0-9-]{0,40}$"
SNAPSHOT_RE = re.compile(r"^[0-9a-f]{8,64}$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,100}$")
SQL_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
TABLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}(\.[a-z_][a-z0-9_]{0,62})?$")


class DefinitionError(Exception):
    def __init__(self, errors: list[dict[str, Any]]):
        super().__init__("; ".join(f"{e['loc']}: {e['msg']}" for e in errors))
        self.errors = errors


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


def _rel(v: str) -> str:
    try:
        validate_relative(v)
    except UnsafePath as exc:
        raise ValueError(str(exc)) from exc
    return v


RelPath = Annotated[str, Field(min_length=1, max_length=1024), AfterValidator(lambda v: v if v == "." else _rel(v))]


class RecoveryPointSelection(Strict):
    """How a concrete, immutable snapshot is chosen before the test starts (PRD §8.4)."""

    policy: Literal["latest", "max_age", "pinned", "random"] = "latest"
    maxAgeHours: int | None = Field(default=None, ge=1, le=24 * 3650)
    snapshotId: str | None = None
    # For policy=random: choose among snapshots no older than this many days.
    randomWithinDays: int | None = Field(default=None, ge=1, le=3650)
    host: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,255}$")
    tags: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9._:=-]{1,100}$")]] = []
    path: str | None = Field(default=None, pattern=r"^/[^\x00]{0,1023}$")
    # No eligible snapshot: "fail" records a failed recovery-point check, "block" marks the run blocked.
    onMissing: Literal["fail", "block"] = "fail"

    @model_validator(mode="after")
    def _consistent(self) -> RecoveryPointSelection:
        if self.policy == "pinned":
            if not self.snapshotId or not SNAPSHOT_RE.match(self.snapshotId):
                raise ValueError("policy 'pinned' needs snapshotId (8-64 lowercase hex characters)")
        elif self.snapshotId:
            raise ValueError("snapshotId is only valid with policy 'pinned'")
        if self.policy == "max_age" and not self.maxAgeHours:
            raise ValueError("policy 'max_age' needs maxAgeHours")
        return self


class SourceSpec(Strict):
    adapter: Literal["restic"] = "restic"
    recoveryPoint: RecoveryPointSelection = RecoveryPointSelection()
    # restic --include patterns (restricts what is restored). Validated so they cannot become flags.
    include: list[Annotated[str, Field(min_length=1, max_length=1024)]] = []

    @field_validator("recoveryPoint", mode="before")
    @classmethod
    def _shorthand(cls, v: Any) -> Any:
        if v == "latest":
            return {"policy": "latest"}
        if isinstance(v, str):
            return {"policy": "pinned", "snapshotId": v}
        return v

    @field_validator("include")
    @classmethod
    def _no_flags(cls, v: list[str]) -> list[str]:
        for p in v:
            if p.startswith("-") or "\x00" in p:
                raise ValueError(f"invalid include pattern {p!r}")
        return v


class RestoreSpec(Strict):
    mode: Literal["isolated"] = "isolated"
    maxDurationSeconds: int = Field(default=1800, ge=10, le=86400)
    # low = nice 19 + idle I/O class, so tests on a production host yield to live services.
    priority: Literal["low", "normal"] = "low"
    # Cap restic's read bandwidth from the repository (KiB/s).
    limitDownloadKiB: int | None = Field(default=None, ge=64)
    maxBytes: int | None = Field(default=None, ge=1)
    # Directory (relative to the restore root) that check paths are relative to. restic restores absolute
    # source paths beneath the target, e.g. a backup of /srv/app lands at <target>/srv/app.
    basePath: str = "."

    @field_validator("basePath")
    @classmethod
    def _base(cls, v: str) -> str:
        v = v.strip("/") or "."
        return v if v == "." else _rel(v)


class Limits(Strict):
    memoryMb: int = Field(default=512, ge=32, le=65536)
    cpus: float = Field(default=1.0, gt=0, le=64)
    pidsLimit: int = Field(default=256, ge=16, le=32768)
    # Relative CPU weight vs. other containers (Docker default 1024). Low by default to favour production.
    cpuShares: int = Field(default=256, ge=2, le=262144)
    # Block-I/O weight (10-1000); only set if your kernel/cgroup setup supports it.
    ioWeight: int | None = Field(default=None, ge=10, le=1000)


class PostgresResource(Strict):
    name: str = Field(pattern=NAME_RE)
    engine: Literal["postgres"] = "postgres"
    version: str = Field(default="16", pattern=r"^\d{2}(\.\d{1,2})?$")
    image: str | None = None
    dumpPath: RelPath
    format: Literal["plain", "custom"] = "plain"
    compression: Literal["none", "gzip"] = "none"
    database: str = Field(default="restored", pattern=SQL_IDENT_RE.pattern)
    readyTimeoutSeconds: int = Field(default=90, ge=5, le=1800)
    importTimeoutSeconds: int = Field(default=900, ge=5, le=86400)
    # Roles referenced by the dump (OWNER TO / GRANT) that must exist before import. Created NOLOGIN.
    createRoles: list[Annotated[str, Field(pattern=SQL_IDENT_RE.pattern)]] = []
    # stop: any SQL error fails the import check. continue: errors are counted and reported.
    onImportError: Literal["stop", "continue"] = "stop"
    limits: Limits = Limits()

    @field_validator("image")
    @classmethod
    def _img(cls, v: str | None) -> str | None:
        if v is not None and not IMAGE_RE.match(v):
            raise ValueError("invalid image reference")
        return v

    @property
    def effective_image(self) -> str:
        return self.image or f"postgres:{self.version}-alpine"


class MariaDBResource(Strict):
    """MariaDB or MySQL restored from a logical dump (mariadb-dump / mysqldump)."""

    name: str = Field(pattern=NAME_RE)
    engine: Literal["mariadb", "mysql"]
    version: str = Field(default="11.4", pattern=r"^\d{1,2}(\.\d{1,2})?$")
    image: str | None = None
    dumpPath: RelPath
    compression: Literal["none", "gzip"] = "none"
    database: str = Field(default="restored", pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    readyTimeoutSeconds: int = Field(default=120, ge=5, le=1800)
    importTimeoutSeconds: int = Field(default=900, ge=5, le=86400)
    onImportError: Literal["stop", "continue"] = "stop"
    limits: Limits = Limits()

    @field_validator("image")
    @classmethod
    def _img(cls, v: str | None) -> str | None:
        if v is not None and not IMAGE_RE.match(v):
            raise ValueError("invalid image reference")
        return v

    @property
    def effective_image(self) -> str:
        return self.image or (f"mariadb:{self.version}" if self.engine == "mariadb" else f"mysql:{self.version}")


def _db_kind(v: Any) -> str:
    engine = v.get("engine", "postgres") if isinstance(v, dict) else getattr(v, "engine", "postgres")
    return "mariadb" if engine in ("mariadb", "mysql") else "postgres"


DatabaseResource = Annotated[Union[Annotated[PostgresResource, Tag("postgres")],
                                   Annotated[MariaDBResource, Tag("mariadb")]], Discriminator(_db_kind)]


class Mount(Strict):
    from_: RelPath = Field(alias="from")
    to: str = Field(pattern=r"^/[A-Za-z0-9._/-]{1,512}$")
    readOnly: bool = True

    @field_validator("to")
    @classmethod
    def _to(cls, v: str) -> str:
        if ".." in v.split("/") or v.rstrip("/") in {"", "/proc", "/sys", "/dev", "/var/run/docker.sock",
                                                        "/run/docker.sock", "/etc"}:
            raise ValueError(f"mount destination {v!r} is not allowed")
        return v


class ServiceResource(Strict):
    name: str = Field(pattern=NAME_RE)
    image: str
    port: int = Field(ge=1, le=65535)
    env: dict[str, Annotated[str, Field(max_length=4096)]] = {}
    mounts: list[Mount] = []
    # Optional argv override (passed as docker args, never through a shell).
    command: list[Annotated[str, Field(max_length=1024)]] | None = None
    user: str | None = Field(default=None, pattern=r"^[0-9]{1,10}(:[0-9]{1,10})?$")
    dependsOn: list[str] = []
    readinessPath: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9._~/?=&%-]{0,512}$")
    readyTimeoutSeconds: int = Field(default=90, ge=5, le=1800)
    readOnlyRootfs: bool = False
    # Linux capabilities kept after --cap-drop ALL. Only a small allowlist is accepted.
    capAdd: list[Literal["CHOWN", "SETUID", "SETGID", "FOWNER", "DAC_OVERRIDE", "NET_BIND_SERVICE", "KILL"]] = [
        "CHOWN", "SETUID", "SETGID", "FOWNER", "DAC_OVERRIDE", "NET_BIND_SERVICE"]
    limits: Limits = Limits()

    @field_validator("image")
    @classmethod
    def _img(cls, v: str) -> str:
        if not IMAGE_RE.match(v):
            raise ValueError("invalid image reference")
        return v

    @field_validator("env")
    @classmethod
    def _env(cls, v: dict[str, str]) -> dict[str, str]:
        for k in v:
            if not ENV_KEY_RE.match(k):
                raise ValueError(f"invalid environment variable name {k!r}")
        return v


class Resources(Strict):
    databases: list[DatabaseResource] = []
    services: list[ServiceResource] = []


class _Check(Strict):
    name: str | None = Field(default=None, max_length=200)
    required: bool = True


class FileExists(_Check):
    type: Literal["file_exists"]
    path: RelPath
    kind: Literal["file", "directory", "any"] = "any"


class FileHash(_Check):
    """sha256 must come from an independent source (a trusted manifest or earlier observation), never from
    the restored copy itself."""

    type: Literal["file_hash"]
    path: RelPath
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class HashManifest(_Check):
    type: Literal["hash_manifest"]
    entries: list[dict[str, str]] = Field(min_length=1, max_length=10000)

    @field_validator("entries")
    @classmethod
    def _entries(cls, v: list[dict[str, str]]) -> list[dict[str, str]]:
        for e in v:
            if set(e) != {"path", "sha256"} or not re.match(r"^[0-9a-f]{64}$", e["sha256"]):
                raise ValueError("each entry needs exactly 'path' and a 64-hex 'sha256'")
            _rel(e["path"])
        return v


class FileSize(_Check):
    type: Literal["file_size"]
    path: RelPath
    minBytes: int | None = Field(default=None, ge=0)
    maxBytes: int | None = Field(default=None, ge=0)


class FileCount(_Check):
    type: Literal["file_count"]
    path: RelPath = "."
    min: int | None = Field(default=None, ge=0)
    max: int | None = Field(default=None, ge=0)
    pattern: str | None = Field(default=None, pattern=r"^[A-Za-z0-9*?._\[\]-]{1,200}$")


class DirNotEmpty(_Check):
    type: Literal["dir_not_empty"]
    path: RelPath


class FilePermissions(_Check):
    type: Literal["file_permissions"]
    path: RelPath
    mode: str | None = Field(default=None, pattern=r"^0?[0-7]{3,4}$")
    uid: int | None = Field(default=None, ge=0)
    gid: int | None = Field(default=None, ge=0)


class FileParse(_Check):
    type: Literal["file_parse"]
    path: RelPath
    format: Literal["json", "yaml"]


class SqliteIntegrity(_Check):
    """Opens a restored SQLite file read-only/immutable and runs PRAGMA integrity_check (or quick_check)."""

    type: Literal["sqlite_integrity"]
    path: RelPath
    mode: Literal["integrity_check", "quick_check"] = "quick_check"
    tables: list[Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")]] = []


class SqliteQuery(_Check):
    type: Literal["sqlite_query"]
    path: RelPath
    query: str = Field(min_length=1, max_length=8192)
    expect: bool | int | float | str | None = True
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte"] = "eq"

    @field_validator("query")
    @classmethod
    def _single_select(cls, v: str) -> str:
        q = v.strip().rstrip(";").strip()
        if ";" in q:
            raise ValueError("only a single SQL statement is allowed")
        if not re.match(r"(?is)^(select|with)\b", q):
            raise ValueError("queries must start with SELECT or WITH (the database is opened read-only)")
        return q


class Inventory(_Check):
    """Records every file under `path` (size + sha256). Compared against a baseline that an administrator
    explicitly approved from an earlier run: an independent, trusted observation, never the current copy."""

    type: Literal["inventory"]
    path: RelPath = "."
    maxFiles: int = Field(default=20000, ge=1, le=200000)
    # Fail when more than this share of baseline files is missing from the new restore (silent data loss).
    maxMissingPercent: float = Field(default=5.0, ge=0, le=100)
    # Fail when total restored size under `path` shrank by more than this vs. the baseline.
    maxShrinkPercent: float = Field(default=25.0, ge=0, le=100)
    # Files whose content changed are expected for live data; they are reported, not failed, unless strict.
    strict: bool = False


class PostgresTableExists(_Check):
    type: Literal["postgres_table_exists"]
    target: str
    table: str = Field(pattern=TABLE_RE.pattern)


class PostgresRowCount(_Check):
    type: Literal["postgres_row_count"]
    target: str
    table: str = Field(pattern=TABLE_RE.pattern)
    min: int | None = Field(default=None, ge=0)
    max: int | None = Field(default=None, ge=0)


class PostgresQuery(_Check):
    type: Literal["postgres_query"]
    target: str
    query: str = Field(min_length=1, max_length=8192)
    expect: bool | int | float | str | None = True
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte"] = "eq"

    @field_validator("query")
    @classmethod
    def _single_select(cls, v: str) -> str:
        q = v.strip().rstrip(";").strip()
        if ";" in q:
            raise ValueError("only a single SQL statement is allowed")
        if not re.match(r"(?is)^(select|with)\b", q):
            raise ValueError("queries must start with SELECT or WITH (they run in a read-only transaction)")
        return q


MYSQL_TABLE = r"^[A-Za-z_][A-Za-z0-9_$]{0,63}$"


class MysqlTableExists(_Check):
    type: Literal["mysql_table_exists"]
    target: str
    table: str = Field(pattern=MYSQL_TABLE)


class MysqlRowCount(_Check):
    type: Literal["mysql_row_count"]
    target: str
    table: str = Field(pattern=MYSQL_TABLE)
    min: int | None = Field(default=None, ge=0)
    max: int | None = Field(default=None, ge=0)


class MysqlQuery(_Check):
    type: Literal["mysql_query"]
    target: str
    query: str = Field(min_length=1, max_length=8192)
    expect: bool | int | float | str | None = True
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte"] = "eq"

    @field_validator("query")
    @classmethod
    def _single_select(cls, v: str) -> str:
        q = v.strip().rstrip(";").strip()
        if ";" in q:
            raise ValueError("only a single SQL statement is allowed")
        if not re.match(r"(?is)^(select|with)\b", q):
            raise ValueError("queries must start with SELECT or WITH (they run as a read-only user)")
        return q


class HttpCheck(_Check):
    type: Literal["http"]
    target: str
    method: Literal["GET", "HEAD"] = "GET"
    path: str = Field(default="/", pattern=r"^/[A-Za-z0-9._~/?=&%:+,-]{0,1024}$")
    expectedStatus: int = Field(default=200, ge=100, le=599)
    bodyContains: str | None = Field(default=None, max_length=1024)
    timeoutSeconds: int = Field(default=10, ge=1, le=300)


Check = Annotated[
    Union[FileExists, FileHash, HashManifest, FileSize, FileCount, DirNotEmpty, FilePermissions, FileParse,
          SqliteIntegrity, SqliteQuery, Inventory, MysqlTableExists, MysqlRowCount, MysqlQuery,
          PostgresTableExists, PostgresRowCount, PostgresQuery, HttpCheck],
    Field(discriminator="type"),
]

FILE_CHECKS = {"file_exists", "file_hash", "hash_manifest", "file_size", "file_count", "dir_not_empty",
               "file_permissions", "file_parse"}
DB_CHECKS = {"postgres_table_exists", "postgres_row_count", "postgres_query"}
SQLITE_CHECKS = {"sqlite_integrity", "sqlite_query"}
MYSQL_CHECKS = {"mysql_table_exists", "mysql_row_count", "mysql_query"}
APP_CHECKS = {"http"}


class Objectives(Strict):
    rpoHours: float | None = Field(default=None, gt=0)
    rtoMinutes: float | None = Field(default=None, gt=0)


class Repository(Strict):
    """Optional repository integrity check before restoring. readDataSubset reads actual pack data
    (e.g. "5%"), which costs I/O; the plain check only verifies structure (PRD §6)."""

    check: bool = False
    readDataSubset: str | None = Field(default=None, pattern=r"^(\d{1,3}(\.\d+)?%|\d+/\d+|\d+[KMGT]?)$")


class Cleanup(Strict):
    deleteTemporaryResources: Literal[True] = True
    preserveEvidence: Literal[True] = True


class Spec(Strict):
    source: SourceSpec = SourceSpec()
    repository: Repository = Repository()
    restore: RestoreSpec = RestoreSpec()
    resources: Resources = Resources()
    checks: list[Check] = Field(min_length=1, max_length=500)
    objectives: Objectives = Objectives()
    cleanup: Cleanup = Cleanup()

    @model_validator(mode="after")
    def _references(self) -> Spec:
        dbs = {d.name for d in self.resources.databases}
        pg = {d.name for d in self.resources.databases if d.engine == "postgres"}
        my = {d.name for d in self.resources.databases if d.engine in ("mariadb", "mysql")}
        svcs = {s.name for s in self.resources.services}
        if dbs & svcs:
            raise ValueError(f"resource names must be unique: {sorted(dbs & svcs)}")
        for i, c in enumerate(self.checks):
            if c.type in DB_CHECKS and c.target not in pg:
                raise ValueError(f"checks[{i}].target {c.target!r} is not a declared PostgreSQL database")
            if c.type in MYSQL_CHECKS and c.target not in my:
                raise ValueError(f"checks[{i}].target {c.target!r} is not a declared MariaDB/MySQL database")
            if c.type in APP_CHECKS and c.target not in svcs:
                raise ValueError(f"checks[{i}].target {c.target!r} is not a declared service resource")
        for s in self.resources.services:
            for d in s.dependsOn:
                if d not in dbs and d not in svcs:
                    raise ValueError(f"service {s.name!r} dependsOn unknown resource {d!r}")
        return self


class Metadata(Strict):
    name: str = Field(pattern=NAME_RE)
    description: str = Field(default="", max_length=2000)


class RecoveryTest(Strict):
    apiVersion: Literal["restoreproof.io/v1alpha1"]
    kind: Literal["RecoveryTest"]
    metadata: Metadata
    spec: Spec


def _errors(exc: ValidationError) -> list[dict[str, Any]]:
    return [{"loc": ".".join(str(p) for p in e["loc"]), "msg": e["msg"]} for e in exc.errors()]


def parse_definition(text: str) -> RecoveryTest:
    if len(text.encode()) > MAX_DEFINITION_BYTES:
        raise DefinitionError([{"loc": "", "msg": "definition too large"}])
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise DefinitionError([{"loc": "", "msg": f"invalid YAML: {exc}"}]) from exc
    if not isinstance(data, dict):
        raise DefinitionError([{"loc": "", "msg": "definition must be a YAML mapping"}])
    try:
        return RecoveryTest.model_validate(data)
    except ValidationError as exc:
        raise DefinitionError(_errors(exc)) from exc


def definition_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def json_schema() -> dict[str, Any]:
    return RecoveryTest.model_json_schema()


def check_label(check: Any, index: int) -> str:
    if check.name:
        return check.name
    target = getattr(check, "target", None) or getattr(check, "path", None) or getattr(check, "table", None)
    return f"{check.type}:{target}" if target else f"{check.type}#{index}"

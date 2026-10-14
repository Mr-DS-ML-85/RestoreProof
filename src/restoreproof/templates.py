"""Built-in recovery-test templates for common self-hosted applications.

A template turns a few form answers into a validated RecoveryTest definition, plus guidance on how to back the
app up so that it is actually restorable. Definitions are produced as data and dumped with yaml.safe_dump, so
answers can never inject YAML structure; the result is then validated by the normal strict schema.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import yaml

from restoreproof.definitions import parse_definition


@dataclass(frozen=True)
class Param:
    key: str
    label: str
    type: str = "string"  # string | int | bool | select | list
    default: Any = None
    help: str = ""
    options: tuple[str, ...] = ()
    required: bool = False


@dataclass(frozen=True)
class Template:
    id: str
    name: str
    category: str
    summary: str
    layers: tuple[str, ...]
    params: tuple[Param, ...]
    build: Callable[[dict[str, Any]], dict[str, Any]]
    backup_guidance: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()
    homepage: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


NAME = Param("name", "Test name", default="", help="lowercase letters, digits and dashes", required=True)
BASE = Param("base_path", "Path inside the snapshot", default=".",
             help="Where the app's directory sits in the snapshot. A backup of /srv/app restores to srv/app. "
                  "Run the test once: if it is wrong, RestoreProof suggests the right value.")
RPO = Param("rpo_hours", "RPO target (hours)", "int", 24, "Warn if the newest snapshot is older than this")
MAXAGE = Param("max_age_hours", "Maximum snapshot age (hours)", "int", 0,
               "0 = always test the latest snapshot; otherwise fail if no snapshot is this recent")
HOST = Param("host", "Snapshot host filter", default="", help="Only consider snapshots from this host (optional)")
TAG = Param("tag", "Snapshot tag filter", default="", help="Only consider snapshots with this tag (optional)")
INVENTORY = Param("inventory", "Detect shrinking backups", "bool", True,
                  "Record every file and compare later runs with a baseline you approve")


def _list(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


def _base(p: dict[str, Any], description: str, checks: list[dict], *, resources: dict | None = None,
          duration: int = 1800, include: list[str] | None = None) -> dict[str, Any]:
    rp: dict[str, Any] = {"policy": "max_age", "maxAgeHours": int(p["max_age_hours"])} if int(
        p.get("max_age_hours") or 0) else {"policy": "latest"}
    if p.get("host"):
        rp["host"] = p["host"]
    if p.get("tag"):
        rp["tags"] = [p["tag"]]
    spec: dict[str, Any] = {
        "source": {"adapter": "restic", "recoveryPoint": rp, **({"include": include} if include else {})},
        "restore": {"mode": "isolated", "maxDurationSeconds": duration, "basePath": p.get("base_path") or "."},
    }
    if resources:
        spec["resources"] = resources
    if p.get("rpo_hours"):
        spec["objectives"] = {"rpoHours": int(p["rpo_hours"])}
    if p.get("inventory"):
        checks = checks + [{"type": "inventory", "name": "inventory", "path": p.get("inventory_path", ".")}]
    spec["checks"] = checks
    spec["cleanup"] = {"deleteTemporaryResources": True, "preserveEvidence": True}
    return {"apiVersion": "restoreproof.io/v1alpha1", "kind": "RecoveryTest",
            "metadata": {"name": p["name"], "description": description}, "spec": spec}


# -- templates ---------------------------------------------------------------------------------------------------

def _generic_files(p: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict] = [{"type": "file_exists", "path": f} for f in _list(p.get("required_files"))]
    for d in _list(p.get("required_dirs")):
        checks.append({"type": "dir_not_empty", "path": d})
    if int(p.get("min_files") or 0):
        checks.append({"type": "file_count", "path": ".", "min": int(p["min_files"])})
    for f in _list(p.get("json_files")):
        checks.append({"type": "file_parse", "path": f, "format": "json"})
    if not checks:
        checks.append({"type": "file_count", "path": ".", "min": 1, "name": "restored-something"})
    return _base(p, "Generic file recovery", checks)


def _postgres_app(p: dict[str, Any]) -> dict[str, Any]:
    db = {"name": "db", "version": str(p["pg_version"]), "dumpPath": p["dump_path"], "database": p["database"],
          "format": p["dump_format"], "compression": "gzip" if str(p["dump_path"]).endswith(".gz") else "none",
          "createRoles": _list(p.get("roles"))}
    checks: list[dict] = [{"type": "postgres_table_exists", "target": "db", "table": t} for t in _list(p.get("tables"))]
    if p.get("nonempty_table"):
        checks.append({"type": "postgres_row_count", "target": "db", "table": p["nonempty_table"], "min": 1})
    if not checks:
        checks.append({"type": "postgres_query", "target": "db", "name": "has-user-tables",
                       "query": "SELECT count(*) FROM information_schema.tables WHERE table_schema "
                                "NOT IN ('pg_catalog','information_schema')", "expect": 1, "op": "gte"})
    return _base(p, "PostgreSQL logical backup", checks, resources={"databases": [db]})


def _vaultwarden(p: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict] = [
        {"type": "sqlite_integrity", "path": "db.sqlite3", "mode": "integrity_check",
         "tables": ["users", "ciphers", "organizations", "devices"]},
        {"type": "sqlite_query", "name": "has-users", "path": "db.sqlite3",
         "query": "SELECT count(*) FROM users", "expect": 1, "op": "gte"},
        {"type": "sqlite_query", "name": "has-vault-items", "path": "db.sqlite3",
         "query": "SELECT count(*) FROM ciphers", "expect": 1, "op": "gte", "required": False},
        {"type": "file_exists", "path": "rsa_key.pem", "kind": "file", "name": "jwt-signing-key"},
    ]
    resources = None
    if p.get("start_app"):
        resources = {"services": [{
            "name": "vaultwarden", "image": p["image"], "port": 80, "readinessPath": "/alive",
            "mounts": [{"from": ".", "to": "/data", "readOnly": False}], "readyTimeoutSeconds": 120,
            "env": {"SIGNUPS_ALLOWED": "false", "INVITATIONS_ALLOWED": "false", "DOMAIN": "http://vaultwarden"},
            "limits": {"memoryMb": 256, "cpus": 1, "pidsLimit": 128}}]}
        checks += [{"type": "http", "target": "vaultwarden", "path": "/alive", "expectedStatus": 200},
                   {"type": "http", "target": "vaultwarden", "path": "/api/config", "expectedStatus": 200,
                    "name": "api-answers"}]
    return _base(p, "Vaultwarden data directory (SQLite) + optional app start", checks, resources=resources,
                 duration=900)


def _home_assistant(p: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict] = [
        {"type": "file_exists", "path": "configuration.yaml", "kind": "file"},
        {"type": "dir_not_empty", "path": ".storage"},
        {"type": "file_parse", "path": ".storage/core.config_entries", "format": "json"},
        {"type": "file_parse", "path": ".storage/auth", "format": "json", "name": "user-accounts"},
    ]
    if p.get("check_recorder"):
        checks.append({"type": "sqlite_integrity", "path": "home-assistant_v2.db", "mode": "quick_check",
                       "tables": ["states", "events"], "required": False, "name": "recorder-history"})
    return _base(p, "Home Assistant configuration directory", checks, duration=1800)


def _paperless(p: dict[str, Any]) -> dict[str, Any]:
    media = p.get("media_dir") or "media"
    checks: list[dict] = [{"type": "dir_not_empty", "path": f"{media}/documents/originals"}]
    resources = None
    if p.get("db_engine") == "postgres":
        resources = {"databases": [{"name": "db", "version": str(p["pg_version"]), "dumpPath": p["dump_path"],
                                    "database": "paperless", "createRoles": ["paperless"],
                                    "compression": "gzip" if str(p["dump_path"]).endswith(".gz") else "none"}]}
        checks += [{"type": "postgres_table_exists", "target": "db", "table": "public.documents_document"},
                   {"type": "postgres_row_count", "target": "db", "table": "public.documents_document", "min": 1}]
    else:
        db = f"{p.get('data_dir') or 'data'}/db.sqlite3"
        checks += [{"type": "sqlite_integrity", "path": db, "tables": ["documents_document"]},
                   {"type": "sqlite_query", "path": db, "name": "has-documents",
                    "query": "SELECT count(*) FROM documents_document", "expect": 1, "op": "gte"}]
    p = {**p, "inventory_path": f"{media}/documents/originals"}
    return _base(p, "Paperless-ngx documents + database", checks, resources=resources, duration=3600)


def _nextcloud(p: dict[str, Any]) -> dict[str, Any]:
    app = (p.get("app_dir") or ".").strip("/") or "."
    pre = "" if app == "." else f"{app}/"
    db = {"name": "db", "version": str(p["pg_version"]), "dumpPath": p["dump_path"], "database": "nextcloud",
          "createRoles": _list(p.get("roles")) or ["nextcloud"],
          "compression": "gzip" if str(p["dump_path"]).endswith(".gz") else "none"}
    checks: list[dict] = [
        {"type": "file_exists", "path": f"{pre}config/config.php", "kind": "file"},
        {"type": "dir_not_empty", "path": f"{pre}{p.get('data_dir') or 'data'}"},
        {"type": "postgres_table_exists", "target": "db", "table": "public.oc_filecache"},
        {"type": "postgres_row_count", "target": "db", "table": "public.oc_users", "min": 1},
        {"type": "postgres_row_count", "target": "db", "table": "public.oc_filecache", "min": 1,
         "name": "has-file-index"},
    ]
    p = {**p, "inventory_path": f"{pre}{p.get('data_dir') or 'data'}"}
    return _base(p, "Nextcloud config, data directory and PostgreSQL", checks, resources={"databases": [db]},
                 duration=3600)


def _immich(p: dict[str, Any]) -> dict[str, Any]:
    db = {"name": "db", "image": p["pg_image"], "dumpPath": p["dump_path"], "database": "immich",
          "compression": "gzip" if str(p["dump_path"]).endswith(".gz") else "none",
          "onImportError": "stop",
          "limits": {"memoryMb": 2048, "cpus": 2, "pidsLimit": 512}}
    lib = p.get("upload_dir") or "upload"
    checks: list[dict] = [
        {"type": "dir_not_empty", "path": lib},
        # Table names verified against a real Immich v3.3.1 database (singular: "asset", "user").
        {"type": "postgres_table_exists", "target": "db", "table": "public.asset"},
        {"type": "postgres_row_count", "target": "db", "table": "public.user", "min": 1, "name": "has-users"},
        {"type": "postgres_row_count", "target": "db", "table": "public.asset", "min": 1, "name": "has-assets"},
    ]
    p = {**p, "inventory_path": lib}
    return _base(p, "Immich photo library + database dump", checks, resources={"databases": [db]}, duration=7200)


def _gitea(p: dict[str, Any]) -> dict[str, Any]:
    data = p.get("data_dir") or "gitea"
    checks: list[dict] = [{"type": "file_exists", "path": f"{data}/conf/app.ini", "kind": "file"},
                          {"type": "dir_not_empty", "path": p.get("repos_dir") or "git/repositories"}]
    resources = None
    if p.get("db_engine") == "postgres":
        resources = {"databases": [{"name": "db", "version": str(p["pg_version"]), "dumpPath": p["dump_path"],
                                    "database": "gitea", "createRoles": ["gitea"]}]}
        checks += [{"type": "postgres_row_count", "target": "db", "table": "public.repository", "min": 1}]
    else:
        db = f"{data}/gitea.db"
        checks += [{"type": "sqlite_integrity", "path": db, "tables": ["repository", "user"]},
                   {"type": "sqlite_query", "path": db, "name": "has-repositories",
                    "query": "SELECT count(*) FROM repository", "expect": 1, "op": "gte"}]
    p = {**p, "inventory_path": p.get("repos_dir") or "git/repositories"}
    return _base(p, "Gitea / Forgejo repositories + database", checks, resources=resources, duration=3600)


COMMON = (BASE, MAXAGE, HOST, TAG, RPO, INVENTORY)
PG_VERSION = Param("pg_version", "PostgreSQL major version", "select", "16",
                   "Must match production (dumps from newer versions may not import into older ones)",
                   options=("12", "13", "14", "15", "16", "17"))
PG_DUMP = Param("dump_path", "Dump file in the snapshot", default="db/dump.sql",
                help="Created by your backup job before restic runs (pg_dump). .gz files are decompressed. "
                     "A pattern such as db/dump-*.sql picks the newest match.")

TEMPLATES: dict[str, Template] = {t.id: t for t in [
    Template("generic-files", "Generic files", "Files", "Any directory: required files, non-empty folders, "
             "JSON that must parse, and shrinkage detection.", ("data",),
             (NAME, *COMMON,
              Param("required_files", "Files that must exist", "list", "", "Comma separated, relative to the path"),
              Param("required_dirs", "Folders that must not be empty", "list", ""),
              Param("json_files", "JSON files that must parse", "list", ""),
              Param("min_files", "Minimum number of files", "int", 0)),
             _generic_files,
             ("Back up the whole directory, not only selected files.",
              "Applications that write while the backup runs can produce half-written files; stop them or use "
              "their export feature first.")),
    Template("postgres-app", "PostgreSQL database", "Databases", "Restore a pg_dump into a throwaway PostgreSQL "
             "and check tables and row counts.", ("data", "database"),
             (NAME, *COMMON, PG_DUMP, PG_VERSION,
              Param("database", "Database name", default="app"),
              Param("dump_format", "Dump format", "select", "plain", "plain = pg_dump; custom = pg_dump -Fc",
                    options=("plain", "custom")),
              Param("roles", "Roles referenced by the dump", "list", "", "Created before import (OWNER TO …)"),
              Param("tables", "Tables that must exist", "list", "", "e.g. public.users, public.orders"),
              Param("nonempty_table", "A table that must have rows", default="")),
             _postgres_app,
             ("Never back up a running PostgreSQL data directory with file tools; back up a dump instead: "
              "`pg_dump -U app app > /srv/app/db/dump.sql` right before `restic backup`.",
              "Make the backup job fail when pg_dump fails (set -e), so a stale dump is never backed up."),
             ("Assertions are examples: an empty table is legitimate for some installs.",)),
    Template("vaultwarden", "Vaultwarden", "Security", "Check the vault database, the JWT signing key, and "
             "optionally start Vaultwarden on the restored data.", ("data", "database", "application"),
             (NAME, *COMMON,
              Param("start_app", "Start Vaultwarden in isolation", "bool", True,
                    "Proves the server can boot from the restored data"),
              Param("image", "Vaultwarden image", default="vaultwarden/server:1.37.4",
                    help="Use the same version you run in production")),
             _vaultwarden,
             ("Back up the whole /data directory (db.sqlite3, rsa_key*, attachments, sends, config.json).",
              "Copying a live SQLite file can capture a torn database. Use `sqlite3 /data/db.sqlite3 "
              "\".backup '/data/db-backup.sqlite3'\"` before the backup, or stop the container."),
             ("Signups and invitations are disabled inside the test instance. It has no network access.",),
             "https://github.com/dani-garcia/vaultwarden"),
    Template("home-assistant", "Home Assistant", "Home automation", "Check configuration.yaml, integrations "
             "(.storage) and, optionally, the recorder database.", ("data", "database"),
             (NAME, *COMMON,
              Param("check_recorder", "Check the history database", "bool", False,
                    "home-assistant_v2.db can be large; the check is advisory")),
             _home_assistant,
             ("Use Home Assistant's built-in backups or back up the full /config directory, including the hidden "
              ".storage folder (it holds integrations, users and devices).",),
             ("configuration.yaml uses HA-specific tags (!include, !secret), so it is checked for presence "
              "only.",), "https://www.home-assistant.io/common-tasks/general/#backups"),
    Template("paperless-ngx", "Paperless-ngx", "Documents", "Check original documents, the document database "
             "(SQLite or PostgreSQL) and detect lost documents.", ("data", "database"),
             (NAME, *COMMON,
              Param("db_engine", "Database", "select", "sqlite", options=("sqlite", "postgres")),
              Param("media_dir", "Media directory", default="media"),
              Param("data_dir", "Data directory (SQLite)", default="data"),
              PG_DUMP, PG_VERSION),
             _paperless,
             ("Run `document_exporter` or back up both media/ and data/ (and a pg_dump when using PostgreSQL).",)),
    Template("nextcloud", "Nextcloud", "Files", "Check config.php, the data directory and the PostgreSQL "
             "database.", ("data", "database"),
             (NAME, *COMMON, PG_DUMP, PG_VERSION,
              Param("app_dir", "Nextcloud folder", default=".",
                    help="Folder holding config/ and data/ (the container's /var/www/html), relative to the path"),
              Param("data_dir", "Data directory", default="data", help="Relative to the Nextcloud folder"),
              Param("roles", "Database roles in the dump", "list", "nextcloud",
                    help="The database user that owns Nextcloud's tables (often nextcloud or oc_admin)")),
             _nextcloud,
             ("Enable maintenance mode (`occ maintenance:mode --on`), pg_dump the database, run restic, then "
              "turn maintenance mode off.",
              "Back up config/, data/ and the dump together in one snapshot so they are consistent."),
             (), "https://docs.nextcloud.com/server/latest/admin_manual/maintenance/backup.html"),
    Template("immich", "Immich", "Photos", "Check the photo library, the database dump and that assets are "
             "present.", ("data", "database"),
             (NAME, *COMMON,
              Param("dump_path", "Database dump in the snapshot", default="backups/immich-db-backup-*.sql.gz",
                    help="Immich's automatic backups are timestamped; a pattern picks the newest one"),
              Param("pg_image", "Postgres image (same as your Immich stack)",
                    default="ghcr.io/immich-app/postgres:14-vectorchord0.4.3-pgvectors0.2.0",
                    help="Immich needs its vector extensions; copy the image from your docker-compose.yml"),
              Param("upload_dir", "Photo directory", default="upload",
                    help="Inside UPLOAD_LOCATION: upload/ by default, library/ if the storage template is on")),
             _immich,
             ("Back up UPLOAD_LOCATION (library, upload, profile) and the database backups folder in the same "
              "snapshot.",),
             ("Verified with Immich v3.3.1. Older Immich versions used plural table names (assets, users).",
              "Thumbnails and encoded video can be regenerated and may be excluded to save space."),
             "https://immich.app/docs/administration/backup-and-restore"),
    Template("gitea", "Gitea / Forgejo", "Development", "Check app.ini, Git repositories and the database.",
             ("data", "database"),
             (NAME, *COMMON,
              Param("db_engine", "Database", "select", "sqlite", options=("sqlite", "postgres")),
              Param("data_dir", "Gitea data directory", default="gitea"),
              Param("repos_dir", "Repositories directory", default="git/repositories"),
              PG_DUMP, PG_VERSION),
             _gitea,
             ("`gitea dump` produces a consistent archive; otherwise stop Gitea or dump the database before the "
              "backup.",)),
]}


def _coerce(param: Param, raw: Any) -> Any:
    if raw is None or raw == "":
        return param.default
    if param.type == "int":
        return int(raw)
    if param.type == "bool":
        return raw if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "yes", "on")
    if param.type == "select" and str(raw) not in param.options:
        raise ValueError(f"{param.label}: choose one of {', '.join(param.options)}")
    if param.type == "list":
        return _list(raw)
    return str(raw)


def render(template_id: str, answers: dict[str, Any]) -> str:
    t = TEMPLATES.get(template_id)
    if t is None:
        raise KeyError(template_id)
    params: dict[str, Any] = {}
    for prm in t.params:
        params[prm.key] = _coerce(prm, answers.get(prm.key))
        if prm.key == "name" and not params["name"]:
            params["name"] = t.id  # same default the dashboard shows
        if prm.required and not params[prm.key]:
            raise ValueError(f"{prm.label} is required")
    params["name"] = re.sub(r"[^a-z0-9-]+", "-", str(params["name"]).lower()).strip("-")[:40] or t.id
    if not params["name"][0].isalpha():
        params["name"] = f"app-{params['name']}"[:40]
    doc = t.build(params)
    header = (f"# Generated from the '{t.name}' template. Edit freely; it is validated on save.\n"
              + "".join(f"# Backup tip: {g}\n" for g in t.backup_guidance))
    text = header + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, width=110)
    parse_definition(text)  # raises DefinitionError with field-level messages
    return text


def describe() -> list[dict[str, Any]]:
    return [{"id": t.id, "name": t.name, "category": t.category, "summary": t.summary, "layers": list(t.layers),
             "backup_guidance": list(t.backup_guidance), "caveats": list(t.caveats), "homepage": t.homepage,
             "params": [{"key": p.key, "label": p.label, "type": p.type,
                        "default": t.id if p.key == "name" else p.default, "help": p.help,
                         "options": list(p.options), "required": p.required} for p in t.params]}
            for t in TEMPLATES.values()]

"""'What to do next' guidance for failed or unrunnable checks and run-level errors.

Hints are deterministic text keyed on the check type / error code, plus context-specific suggestions computed
from the restored tree during the run (e.g. a similarly named file elsewhere, or a likely basePath).
"""

from __future__ import annotations

import difflib
import os
from pathlib import Path

ERROR_HINTS: dict[str, str] = {
    "auth_failed": "The repository rejected the password. Update the source credentials (Sources → edit) with "
                   "the password your backup job uses, then press Validate access.",
    "repository_unavailable": "The repository could not be opened. Check that the path or URL is right, that the "
                              "storage is mounted/reachable from the worker, and that backend credentials "
                              "(e.g. AWS_ACCESS_KEY_ID) are set on the source.",
    "repository_locked": "Another restic process holds an exclusive lock (often a running backup or prune). "
                         "The test will retry; if it persists, check for stale locks with `restic list locks`.",
    "recovery_point_missing": "No snapshot matched the recovery-point policy. Confirm backups are still running, "
                              "and that host/tag/path filters in the definition match `restic snapshots` output.",
    "budget_exceeded": "The restore is larger than maxBytes. Raise spec.restore.maxBytes, or restrict what is "
                       "restored with spec.source.include.",
    "insufficient_disk": "Not enough free disk for this restore. Free space on the RestoreProof data volume or "
                         "lower RESTOREPROOF_MIN_FREE_BYTES only if you are sure.",
    "disk_low": "Free disk dropped below the safety threshold during the restore, so it was stopped. "
                "Free space and run the test again.",
    "timeout": "The test exceeded maxDurationSeconds. Raise the limit, restore less (spec.source.include), or "
               "check repository/network throughput. The measured time is useful RTO evidence.",
    "secret_unavailable": "Stored credentials cannot be decrypted. The key file (RESTOREPROOF_SECRET_KEY_FILE) "
                          "differs from the one used to save them. Restore the original key or re-enter credentials.",
    "invalid_definition": "The saved test definition no longer validates. Open the application and fix the "
                          "errors shown by Validate.",
    "worker_interrupted": "The worker stopped mid-run (crash, restart or reboot). Temporary resources were "
                          "reconciled. If this repeats, check the worker's memory limit and logs.",
    "evidence_persist_failed": "The report could not be written. Check free space and permissions on the "
                               "reports directory, then run the test again.",
    "internal_error": "RestoreProof hit an unexpected error. The sanitized log on this page has details; "
                      "please report it with the run ID.",
}

CHECK_HINTS: dict[str, str] = {
    "repository_access": ERROR_HINTS["auth_failed"],
    "recovery_point_selected": ERROR_HINTS["recovery_point_missing"],
    "repository_integrity": "restic check found repository damage. Run `restic check --read-data` on the "
                            "repository host, repair with `restic repair index/snapshots` per the restic docs, and "
                            "make a fresh backup. Do not rely on affected snapshots.",
    "restore": "restic could not restore every file. Look at the errors in the details and the sanitized log; "
               "damaged packs show up here. Run a repository check with readDataSubset.",
    "restore_base_present": "basePath does not exist in the restored data. restic restores absolute paths: a "
                            "backup of /srv/app lands at srv/app. Use the suggestion below or inspect the snapshot "
                            "with `restic ls <id>`.",
    "file_exists": "The file is not in this snapshot. Make sure the backup job includes it and that the path "
                   "is relative to basePath.",
    "file_hash": "The restored file's content differs from the expected hash. Either the file legitimately "
                 "changed (update the expected hash from a trusted source) or the backup captured a damaged or "
                 "partial copy.",
    "hash_manifest": "Some files are missing or differ from the manifest. Regenerate the manifest when the source "
                     "changes, and check the listed paths.",
    "file_size": "The file size is outside the expected range. A tiny file often means the backup captured an "
                 "empty or truncated file (e.g. an app writing while the backup ran).",
    "file_count": "Fewer/more files than expected were restored. Check the backup's include/exclude rules.",
    "dir_not_empty": "The directory restored empty. The data likely lives on a volume the backup job does not "
                     "include (check Docker volume mount points).",
    "file_permissions": "Permissions differ from what the application needs. Restore with matching ownership "
                        "(run restic as root) or fix them in your recovery runbook.",
    "file_parse": "The file is corrupt or truncated. If the app writes it continuously, back it up from a "
                  "consistent export or stop the app during the backup.",
    "sqlite_integrity": "The SQLite database is damaged or incomplete. Copying a live SQLite file is unsafe: "
                        "back it up with `sqlite3 db .backup` or the app's own export, or stop the app first. "
                        "If a -wal file exists in production, include it in the backup.",
    "sqlite_query": "The database opened, but your invariant does not hold. Check whether the data really "
                    "changed or the query needs updating.",
    "inventory": "Files that existed in the trusted baseline are gone, or the data shrank sharply. Check whether "
                 "they were intentionally deleted; if so, approve a new baseline. Otherwise your backup is "
                 "silently losing data (moved volume, changed exclude rule, failed mount).",
    "postgres_dump_present": "The dump file is not in the snapshot. Make sure the backup job runs pg_dump before "
                             "restic, writes to the path in dumpPath, and that the dump step did not fail.",
    "postgres_ready": "PostgreSQL did not start. The container log is in the details. A version mismatch "
                      "with the dump or too little memory are common causes.",
    "postgres_started": "The database container could not be started. Check that Docker is available to the "
                        "worker and that the image can be pulled.",
    "postgres_import": "The dump could not be imported. Missing roles: add them to createRoles. Version "
                       "features: match the production PostgreSQL version. Truncated dump: the backup copied it "
                       "before pg_dump finished.",
    "postgres_table_exists": "The database imported, but the table is not there. The dump may be of the wrong "
                             "database, a different schema, or taken before the app migrated.",
    "postgres_row_count": "The table exists but has an unexpected number of rows. An empty table usually means "
                          "the dump came from a fresh/empty instance.",
    "postgres_query": "The database is up, but your invariant does not hold. Check the data or update the "
                      "query if the schema changed.",
    "mariadb_dump_present": "The MariaDB/MySQL dump is not in the snapshot. Run `mariadb-dump --single-transaction "
                            "-u root -p DB > dump.sql` (or mysqldump) before the backup, into a folder the backup includes.",
    "mysql_dump_present": "The MySQL dump is not in the snapshot. Run `mysqldump --single-transaction` before the backup.",
    "mariadb_ready": "MariaDB did not start. Check the container log in the details (memory, image version).",
    "mysql_ready": "MySQL did not start. Check the container log in the details (memory, image version).",
    "mariadb_import": "The dump could not be imported. Use a version at least as new as production, and dump with "
                      "--single-transaction so the dump is consistent.",
    "mysql_import": "The dump could not be imported. Use a version at least as new as production.",
    "mysql_table_exists": "The database imported, but the table is missing: wrong database dumped, a different table "
                          "prefix (WordPress: wp_ by default), or the app had not been installed yet.",
    "mysql_row_count": "The table exists but has an unexpected number of rows; an empty table usually means the dump "
                       "came from an empty or fresh instance.",
    "mysql_query": "The database is up, but your invariant does not hold. Check the data or update the query.",
    "service_ready": "The application container did not become ready. Read the container log in the details: "
                     "missing config files, secrets or environment variables are the usual cause.",
    "http": "The application started but did not answer as expected. A 500 usually means it cannot read its "
            "restored data or config; a different body may mean it started in setup mode (data not found).",
    "docker": "Docker is not reachable by the worker. Database and application checks need it.",
    "rpo": "The newest usable snapshot is older than your RPO. Check that the backup schedule is running.",
    "rto": "Recovery took longer than your RTO target. Real recoveries are often slower; plan accordingly.",
    "preflight": ERROR_HINTS["insufficient_disk"],
}


MISSING_HINT = ("This path is not in the restored snapshot. Either the backup job does not include it, or "
                "basePath does not match how the backup was taken (the run page shows where similarly named files were found). Inspect the "
                "snapshot with `restic ls <snapshot>`.")


def infer_base_path(current_base: str, pairs: list[tuple[str, list[str]]]) -> str | None:
    """If several missing paths were all found under the same extra prefix, that prefix is the real basePath.

    pairs: (missing_path, [where similarly named files were found, relative to the restore root]).
    """
    votes: dict[str, int] = {}
    cur = "" if current_base in ("", ".") else current_base.strip("/")
    for missing, found in pairs:
        for f in found:
            if f == missing or not f.endswith("/" + missing):
                continue
            prefix = f[: -len(missing) - 1]
            if cur and not (prefix == cur or prefix.startswith(cur + "/")):
                continue
            votes[prefix] = votes.get(prefix, 0) + 1
            break
    if not votes:
        return None
    best, n = max(votes.items(), key=lambda kv: kv[1])
    return best if n >= max(1, (len(pairs) + 1) // 2) and best != cur else None


def hint_for(check_type: str, name: str = "") -> str | None:
    key = name.split(":")[0] if name.split(":")[0] in CHECK_HINTS else check_type
    return CHECK_HINTS.get(key)


def suggest_similar_path(root: Path, wanted: str, limit_files: int = 50000) -> list[str]:
    """Find restored paths that end with the same file name (or a close one) as `wanted`."""
    target = Path(wanted).name
    exact, names, seen = [], {}, 0
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        for f in files + dirs:
            seen += 1
            if seen > limit_files:
                break
            rel = os.path.relpath(os.path.join(dirpath, f), root)
            if f == target:
                exact.append(rel)
            else:
                names.setdefault(f, rel)
    if exact:
        return sorted(exact, key=len)[:5]
    return [names[n] for n in difflib.get_close_matches(target, list(names), n=3, cutoff=0.75)]


def suggest_base_path(restore_root: Path, wanted: str = "", max_depth: int = 12) -> list[str]:
    """Candidate basePath values.

    1. Directories whose path ends with the configured basePath (an absolute-path backup such as
       /home/me/srv/app restores to home/me/srv/app, so `srv/app` should become `home/me/srv/app`).
    2. Otherwise, the first directory below the root that branches (contains more than one entry or files).
    """
    wanted = wanted.strip("/")
    out: list[str] = []
    if wanted and wanted != ".":
        tail = Path(wanted).name
        for dirpath, dirs, _files in os.walk(restore_root, followlinks=False):
            depth = len(Path(dirpath).relative_to(restore_root).parts)
            if depth >= max_depth:
                dirs[:] = []
                continue
            rel = Path(dirpath).relative_to(restore_root).as_posix()
            if Path(dirpath).name == tail and (rel == wanted or rel.endswith("/" + wanted)):
                out.append(rel)
            if len(out) >= 3:
                break
        if out:
            return sorted(out, key=len)
    cur = restore_root
    for _ in range(max_depth):
        entries = [e for e in cur.iterdir() if not e.name.startswith(".restoreproof")] if cur.is_dir() else []
        dirs = [e for e in entries if e.is_dir() and not e.is_symlink()]
        if len(entries) == 1 and dirs:
            cur = dirs[0]
            continue
        break
    rel = cur.relative_to(restore_root).as_posix()
    out.append(rel or ".")
    if cur.is_dir():
        out += [d.relative_to(restore_root).as_posix() for d in sorted(cur.iterdir())
                if d.is_dir() and not d.is_symlink()][:5]
    return out[:6]

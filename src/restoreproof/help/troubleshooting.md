# When a test fails

First, open the failed run (**Runs** → the red line). Every failed check has a blue **What to do next**
box written for that exact problem. This page collects the most common ones.

## "This path is not in the restored snapshot"

The file isn't where the test expects it.

- If the run says **"Likely cause found: set basePath to …"**, press the button. It fixes the test and runs it again.
- Otherwise use **Sources → Browse files** and look for the file. Maybe your backup job doesn't include that folder at all.

## "The repository rejected the password"

The password saved in RestoreProof doesn't match the backup. Fix it under **Sources** (Remove, then add it
again with the right password).

## "Repository not reachable" / inconclusive

The backup location was offline (NAS asleep, USB disk not mounted, internet down). RestoreProof retries a
few times. If it keeps happening, check the mount or network on the RestoreProof machine.

## "database is damaged or incomplete" (SQLite)

The database file was copied while the app was writing to it. Fix the **backup**, not the test:
- stop the app during the backup, or
- add a `sqlite_backup` step (see [Backups](#/help/backups)), or
- use the app's own export feature.

## "The dump file is not in the snapshot" (PostgreSQL / MariaDB)

These databases need a **dump file** in the backup. Copying their data folder is not enough. Make your
backup script run `pg_dump` or `mariadb-dump` **before** restic, and make it stop if the dump fails.

## "import failed"

- *role does not exist*: add the role to `createRoles` in the test (PostgreSQL).
- Version errors: use the same database version as production, or newer.

## "N baseline files are missing"

Files that existed when you trusted the baseline are gone from the backup. Either you deleted them on purpose
(open the run → **use this run as the new baseline**), or your backup is **silently losing data**, for
example a moved volume or a new exclude rule. Take this one seriously.

## "The application started but did not answer as expected"

The app couldn't read its restored data or config. Open **details → container_log** on the failed check;
the app usually says what is missing.

## The test never starts

Look at **Settings → Workers**:
- **No worker online**: start it (`docker compose up -d worker`, or `sudo systemctl start restoreproof-worker`).
- **"waiting: host busy"**: the server is very busy, so tests wait. Change the limit in **Settings → Protect production**.
- **"waits for the maintenance window"**: scheduled tests only start in the window you set. Manual tests always run.

## I added something by mistake

- An **application**: open it → **Danger zone** → Delete. You can keep or remove its past results.
- A **source**: **Sources** → Remove. RestoreProof tells you if a test still uses it. Your backup files are never deleted.
- A **backup plan**: its page → **Danger zone**.

## Still stuck?

Run `restoreproof doctor` (or **Settings → Health check**). It checks restic, Docker, disk space, keys,
the database and the workers, and says how to fix each problem.

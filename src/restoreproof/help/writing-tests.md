# Writing a test

A **test** describes what "my app came back correctly" means. Templates write it for you. This page explains
the result, so you can change it or write one yourself (Applications → Protect an application → Write your own).

Tests are written in **YAML** (JSON works too). Indentation matters: use spaces, never tabs.

## The smallest useful test

```yaml
apiVersion: restoreproof.io/v1alpha1
kind: RecoveryTest
metadata:
  name: my-photos              # a-z, 0-9 and dashes; must be unique
spec:
  restore:
    basePath: "home/me/photos" # the app's folder inside the backup (see below)
  checks:
    - type: dir_not_empty
      path: "2026"
    - type: file_count
      path: "."
      min: 100
```

This says: restore the latest backup, go to `home/me/photos`, and check that the folder `2026` has files and
that there are at least 100 files in total.

## basePath: the most important setting

restic stores the *full path* of what you backed up. If you backed up `/srv/vaultwarden`, the restored copy
contains `srv/vaultwarden/db.sqlite3`. So:

| You backed up | basePath | Then check paths like |
|---|---|---|
| `/srv/vaultwarden` | `srv/vaultwarden` | `db.sqlite3` |
| `/home/me` (and the app is in `docker/nextcloud`) | `home/me/docker/nextcloud` | `config/config.php` |
| `.` from inside the app folder (`cd /srv/app && restic backup .`) | `.` | `data/settings.json` |

**Don't guess:** use **Sources → Browse files**, or **Browse your backup** in the template form. If you get
it wrong anyway, the failed run says *"Likely cause found: set basePath to …"* with a fix button.

## Choosing which backup to test

```yaml
spec:
  source:
    recoveryPoint: latest                          # the newest snapshot (default)
    # recoveryPoint: {policy: max_age, maxAgeHours: 36}   # fail if the newest is older than 36 h
    # recoveryPoint: {policy: latest, host: nas, tags: [nightly]}
    # recoveryPoint: {policy: random, randomWithinDays: 30}  # sometimes test an older one
```

## File checks

| Check | What it proves | Example |
|---|---|---|
| `file_exists` | the file or folder is there | `{type: file_exists, path: config.yaml, kind: file}` |
| `dir_not_empty` | the folder has at least one file | `{type: dir_not_empty, path: uploads}` |
| `file_count` | enough (or not too many) files | `{type: file_count, path: photos, min: 1000}` |
| `file_size` | not empty / not truncated | `{type: file_size, path: db.sqlite3, minBytes: 100000}` |
| `file_parse` | JSON/YAML is not corrupt | `{type: file_parse, path: settings.json, format: json}` |
| `file_hash` | exact content (hash from a trusted source) | `{type: file_hash, path: key.pem, sha256: "…64 hex…"}` |
| `file_permissions` | owner and mode survived | `{type: file_permissions, path: data, mode: "0750"}` |
| `inventory` | **the backup did not silently shrink** | `{type: inventory, path: "."}` |

How `inventory` works: on the first run it records every file. Open that run and press **Trust this run as the
baseline**. From then on, the test fails if more than 5% of those files disappear or the data shrinks by more
than 25%. You can change the limits with `maxMissingPercent` and `maxShrinkPercent`.

## Database checks

**SQLite** (Vaultwarden, Home Assistant, Gitea, Grafana, the *arr apps…):

```yaml
    - {type: sqlite_integrity, path: db.sqlite3, tables: [users, ciphers]}
    - {type: sqlite_query, path: db.sqlite3, query: "SELECT count(*) FROM users", expect: 1, op: gte}
```

**PostgreSQL** or **MariaDB/MySQL**: your backup must contain a *dump file* (made with `pg_dump` or
`mariadb-dump`). RestoreProof starts a temporary database, loads the dump and asks it questions.

```yaml
spec:
  resources:
    databases:
      - {name: db, version: "16", dumpPath: db/dump.sql, database: app}                     # PostgreSQL
      - {name: wp, engine: mariadb, version: "11.4", dumpPath: db/wp.sql, database: wordpress}  # MariaDB
  checks:
    - {type: postgres_table_exists, target: db, table: public.users}
    - {type: postgres_row_count, target: db, table: public.users, min: 1}
    - {type: mysql_table_exists, target: wp, table: wp_posts}
    - {type: mysql_query, target: wp, query: "SELECT COUNT(*) FROM wp_users", expect: 1, op: gte}
```

`op` can be `eq`, `ne`, `gt`, `gte`, `lt` or `lte`. Queries must start with `SELECT` or `WITH`. They run as a
read-only user, so a test can never change the data.

## Starting the real app

```yaml
spec:
  resources:
    services:
      - name: web
        image: nginx:1.27-alpine
        port: 80
        mounts: [{from: www, to: /usr/share/nginx/html}]
  checks:
    - {type: http, target: web, path: /, expectedStatus: 200, bodyContains: "Welcome"}
```

The app runs on a private network with **no internet access**, and is deleted afterwards.

## Optional checks

Add `required: false` to a check that should warn but not fail the test:

```yaml
    - {type: sqlite_query, path: db.sqlite3, query: "SELECT count(*) FROM attachments", expect: 1, op: gte, required: false}
```

## Limits and being gentle on your server

```yaml
spec:
  restore:
    maxDurationSeconds: 1800    # give up after 30 minutes
    maxBytes: 21474836480       # never restore more than 20 GB
    priority: low               # default: lowest CPU/disk priority
    limitDownloadKiB: 20480     # read at most 20 MB/s from the backup
  objectives:
    rpoHours: 24                # warn if the newest backup is older than a day
    rtoMinutes: 60              # warn if restoring took longer than an hour
```

## Common mistakes

- **Tabs instead of spaces**: YAML needs spaces.
- **Leading slash in paths**: write `config.yaml`, not `/config.yaml`. Paths are relative to `basePath`.
- **`..` in paths**: not allowed, for safety.
- **Same name twice**: each test needs its own `metadata.name`.

Press **Validate** before saving: it points to the exact line that is wrong.

# Changelog

## 0.3.0 — 2026-10-15

### Added
- **Backup module (optional).** Plans back up folders with restic to an ordered list of destinations, and the
  first one that fits is used. Local disks have a free-space guard and fall back to remote. Destinations:
  local, SFTP/SCP (another Linux server, pinned host key with a fetch-and-confirm flow), SMB, WebDAV/Nextcloud,
  FTP/FTPS, restic REST server, S3-compatible, Backblaze B2, Google Drive. Every run records why each
  destination was chosen or skipped. Consistency hooks (`sqlite_backup`, `postgres_dump`, `pause_container`),
  opt-in retention scoped to the plan, `partial` status when files could not be read, and recovery tests
  queued automatically after each backup. Every destination can also be used by recovery tests. See
  `docs/backups.md`. Each protocol is tested against a real server.
- **No Docker required.** `install-native.sh` + hardened systemd units for Proxmox LXC, VMs and bare metal,
  verified under systemd with Ubuntu 24.04's restic 0.16.4.
- **ARM64.** Multi-arch image (Raspberry Pi 4/5, Ampere); the test suite runs inside the arm64 image in CI.
- **Protecting production.** Restores run at nice 19 / idle I/O class by default; optional bandwidth cap
  (`limitDownloadKiB`), container CPU and I/O weights, "pause while host is busy", and maintenance windows.
- **Scheduling semantics documented** (`docs/scheduling.md`).
- **Real-application test suite** (`tests/realapps`, opt-in): every template runs against the real upstream
  image and data. Vaultwarden 1.37.4, Gitea 28.1, Immich v3.3.1, Nextcloud 35.0.1, Paperless-ngx 3.3.1 and
  Home Assistant 2026.10.1 all pass.
- Example Recovery Readiness Report (HTML + PDF) from a real run, linked from the landing page.

### Fixed
- Immich template: v3 uses singular table names (`asset`, `user`), timestamped dumps (`dumpPath` now
  accepts a glob; the newest match wins), and the correct vectorchord Postgres image tag.
- Vaultwarden template: current image tag (1.37.4).
- Nextcloud template: the Nextcloud folder and the dump can sit side by side in the snapshot (new
  "Nextcloud folder" field).
- gzip dump import failed on Debian-based Postgres images (`/bin/sh` is dash, which has no `pipefail`).
- Health check: restic 0.16 is supported (0.17+ recommended), and `0640` key files with a dedicated group are fine.
- Native re-install now restarts the services so upgrades take effect.

## 0.2.0 — 2026-10-14

Product release: protect an app without writing YAML, and understand every failure.

### Added
- **Guided setup.** A new administrator is taken through: connect a repository, check access, pick an app,
  run the first test, schedule it.
- **Application templates.** Vaultwarden, Home Assistant, Paperless-ngx, Nextcloud, Immich, Gitea/Forgejo,
  PostgreSQL and generic files. Each fills in a form, shows how to back that app up correctly, and produces
  a validated definition (`docs/templates.md`).
- **SQLite checks.** `sqlite_integrity` (`integrity_check`/`quick_check` + expected tables) and
  `sqlite_query`. Databases are opened read-only with a statement authorizer. Restored `-wal` files are applied
  on a scratch copy.
- **Shrinking-backup detection.** The `inventory` check records every file. You approve a run as the trusted
  baseline, and later runs fail when baseline files go missing or the data shrinks beyond a threshold.
- **"What to do next" on every failure.** Cause-specific remediation for each check type and error code.
  The run page shows where a missing file actually is in the snapshot, and offers a one-click
  "set basePath and re-run" fix when the backup was taken from a different directory level.
- **Recovery Readiness Report.** Cross-application verdicts (ready / stale / at risk / not ready /
  untested), verified depth, pass rate, failing checks and next steps. Printable HTML with organization
  branding, plus hashed JSON.
- **Notifications say what to fix.** Payloads include the failing check and the next step.
- **Evidence retention** configurable from Settings (logs, inventories, reports). Only files are removed;
  results and hashes stay, and the latest passing report of each app is always kept.
- **Health check.** `restoreproof doctor` and Settings → Health check (restic version, Docker, disk, key
  permissions, database, workers).
- **One-command install.** `./install.sh [--repo PATH]` generates secrets, mounts repositories read-only,
  starts the stack and runs the health check.
- Gzip-compressed PostgreSQL dumps (`compression: gzip`, detected automatically for `.gz` in templates).
- Test depth shown per application (Snapshot · Files · Database · App).

### Changed
- RestoreProof is free to use, with no paid tiers. The website lists no prices.
- Migrations 0002/0003 (additive). Baselines are stored in the metadata database, and existing ones are
  backfilled.

## 0.1.0 — 2026-10-14

First release: Restic adapter, isolated restores, file/PostgreSQL/HTTP checks, durable job state machine,
signed evidence, scheduler, notifications, dashboard, Docker Compose deployment.

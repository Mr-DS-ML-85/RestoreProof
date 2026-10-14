# RestoreProof

**Know your backups can bring your apps back, before you need them.**

Your backup job says "success". That only means files were copied. RestoreProof regularly restores your
backups into a sealed-off sandbox, starts the database and the app, checks they really work, and tells you
in plain language what is broken and how to fix it. Each test leaves a signed report.

Self-hosted. Docker, Proxmox LXC or bare metal. x86-64 and ARM64 (Raspberry Pi 4/5). No cloud account, no
telemetry, nothing leaves your network.

```bash
git clone <this repository> restoreproof && cd restoreproof
./install.sh --repo /mnt/backups/restic        # Docker; then open http://127.0.0.1:8080
sudo ./install-native.sh                       # or: no Docker, systemd services (LXC, VM, bare metal)
```

Don't have backups yet? The optional [backup module](docs/backups.md) makes restic backups to a local disk
when there's room, otherwise to another server, NAS (SFTP, SMB, WebDAV/Nextcloud, FTP), S3/B2 or Google Drive,
and then proves they restore. See an [example Readiness Report](website/example-report.pdf).

The guided setup connects your Restic repository, lets you pick your app, and runs the first recovery test
in about five minutes.

---

## What it catches that a green backup job doesn't

| Situation | What you'd see without RestoreProof | What RestoreProof reports |
|---|---|---|
| The database was copied while the app was writing | "Backup OK" | `sqlite_integrity` failed: *back it up with `sqlite3 .backup` or stop the app first* |
| The backup job lost a volume after a compose change | "Backup OK", just smaller | `inventory`: *412 of 9,830 baseline files are missing* |
| `pg_dump` failed but the job carried on | "Backup OK" | `postgres_table_exists` failed: *the dump came from an empty database* |
| The files restore, but the app won't start | Nothing, until the day you need it | `service_ready` failed, with the container log |
| The backup path differs from what you expected | Confusion during a real outage | *Likely cause found: set basePath to `srv/app`* (one click, re-run) |
| The newest snapshot is three days old | Nothing | RPO warning, and an alert |
| Wrong repository password after a rotation | Discovered during the disaster | Failed on the next nightly test, with the exact fix |

## How a test works

1. **Snapshot**: resolve the policy (latest, max age, pinned, random) to one immutable snapshot ID.
2. **Files**: restore into a fresh, private directory (`restic restore --verify`). Check required files,
   hashes, permissions and parsable configs, and compare against a trusted baseline to catch silent shrinkage.
3. **Database**: SQLite opened read-only, or the PostgreSQL dump imported into a throwaway server, then
   checked with read-only queries.
4. **App**: the real application image started on an internal network with no internet access and no
   ports published, then health-checked over HTTP.
5. **Evidence**: per-layer results, timings and a signed manifest are saved. Every temporary file, container
   and network is then removed, and cleanup is tracked and reported separately.

A check that *could not run* never counts as a pass: the run is marked `inconclusive`.

## Ready-made templates

Vaultwarden · Home Assistant · Paperless-ngx · Nextcloud · Immich · Gitea/Forgejo · PostgreSQL · any
directory. Each template asks a few questions, explains how to back that app up so it is actually restorable,
and generates a validated test you can still edit by hand. See [docs/templates.md](docs/templates.md).

## For people who look after other people's systems

- **Recovery Readiness Report**: one printable page per installation with a verdict for each application
  (ready / stale / at risk / not ready / untested), what was verified, the 30-day pass rate and the next
  steps. Add your client's name and your footer.
- Alerts by ntfy, email or webhook that include the failing check and the fix.
- Audit trail of every configuration change, credential update and test run.
- Roles: viewer, operator, admin.

## Requirements

| | |
|---|---|
| OS | Linux (Docker Compose, or any systemd host incl. Proxmox LXC) |
| CPU | x86-64 or ARM64 |
| restic | ≥ 0.16 (0.17+ recommended) |
| Docker | for PostgreSQL and application checks; file and SQLite checks work without it (Podman: experimental) |
| rclone | only for SMB / WebDAV / FTP / Google Drive backup destinations (included in the Docker image) |

When tests run, what happens on overlap, retries and missed runs, and how tests stay out of production's
way: [docs/scheduling.md](docs/scheduling.md).

## Safety by design

- **Recovery tests are read-only**: they only ever issue `snapshots`, `stats`, `check`, `restore` and `cat`
  to restic. Writing (`init`, `backup`, and opt-in `forget`/`prune`) is confined to the separate backup module.
- **Polite on a shared host**: restores run at the lowest CPU and I/O priority, and can be bandwidth-capped,
  paused while the host is busy, or kept to a maintenance window.
- Restores go only into marker-owned directories under one root. Cleanup refuses to delete anything else.
- Test containers: internal network, `--cap-drop ALL`, no privileged mode, no Docker socket, CPU/memory/PID limits.
- Credentials are encrypted with a key kept outside the database and redacted from every log, report and alert.
- A crashed worker never turns into a false pass. Interrupted runs are reconciled and retried a bounded number of times.

Details: [threat model](docs/threat-model.md) · [architecture](docs/architecture.md).

## Commands

```bash
restoreproof doctor            # is this installation able to run meaningful tests?
restoreproof templates         # list app templates
restoreproof validate t.yaml   # validate a hand-written test definition
restoreproof verify-report manifest.json --fingerprint <key>   # check a report was not altered
restoreproof reconcile         # clean up after a crash right now
```

The REST API is at `/api/v1` (OpenAPI at `/docs`); see [docs/installation.md](docs/installation.md).

## Development

```bash
uv venv && uv pip install -e '.[dev,postgres]'
.venv/bin/pytest          # real restic repositories, real PostgreSQL and app containers
```

The suite deliberately breaks things (wrong passwords, corrupted repositories, torn SQLite files, shrinking
backups, hung restores, worker crashes, forged cleanup paths) and requires that none of them produce a pass.

[Changelog](CHANGELOG.md) · [Recovery reports format](docs/recovery-reports.md) · [Backup adapters](docs/backup-adapters.md) · MIT licensed

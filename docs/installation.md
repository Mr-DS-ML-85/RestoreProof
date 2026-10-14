# Installation and upgrades

## Requirements

Linux host with Docker Engine and the compose plugin, plus disk space for the largest restore you will test
plus `RESTOREPROOF_MIN_FREE_BYTES` (default 1 GiB) of headroom. Nothing else is needed: no Redis, Kubernetes or GPU.

## Quick install

```bash
git clone <this repository> restoreproof && cd restoreproof
./install.sh --repo /mnt/backups/restic          # repeat --repo for each local repository; omit for remote ones
```

The installer checks Docker, writes `.env` with a random database password, generates the credential key,
mounts each `--repo` read-only into the worker at `/repos/1`, `/repos/2`, …, starts the stack, and runs
`restoreproof doctor`. Re-running it never overwrites existing secrets or data. Open
`http://127.0.0.1:8080`; the guided setup takes it from there.

Options: `--data /srv/restoreproof` (default `/var/lib/restoreproof`), `--port 8080`.

## Install without Docker (Proxmox LXC, VM, bare metal)

```bash
sudo apt install python3 python3-venv restic      # Debian/Ubuntu; rclone too for SMB/WebDAV/FTP/Drive backups
git clone <this repository> restoreproof && cd restoreproof
sudo ./install-native.sh                          # --listen 0.0.0.0 to reach it from your LAN
```

This installs into `/opt/restoreproof`, data in `/var/lib/restoreproof`, config and key in
`/etc/restoreproof/`, and enables two hardened services, `restoreproof-web` and `restoreproof-worker` (with the
scheduler). The worker runs at `Nice=10` with the idle I/O class. Re-run the script to upgrade: it keeps
config, key and data, and restarts the services.

- **Proxmox LXC:** works in unprivileged containers. Bind-mount your restic repository or backup folders into
  the container, and allow writes with `systemctl edit restoreproof-worker` → `[Service] ReadWritePaths=/mnt/backups`.
- **Container checks without Docker:** file and SQLite checks run natively. PostgreSQL and application
  checks need Docker (`usermod -aG docker restoreproof`) or, experimentally, Podman (`--podman`). Without
  either, those checks are reported as "could not run", never as passed.

## Install with Docker Compose (manual)

```bash
git clone <this repository> restoreproof && cd restoreproof
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD to a long random value, set RESTOREPROOF_HOST_DATA to an absolute path.
sudo mkdir -p /var/lib/restoreproof

# Credential-encryption key (Fernet). Keep a copy somewhere safe and separate from your DB backups.
mkdir -p secrets
(umask 077; python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())' > secrets/restoreproof.key)
sudo chown 10001 secrets/restoreproof.key       # the unprivileged web/scheduler user must read it

docker compose up -d --build
```

Mount each local restic repository into the worker **read-only** by editing the `worker.volumes` section of
`compose.yaml` (for example `/mnt/backups/restic:/repos/main:ro`), then use `/repos/main` as the repository
path. Remote repositories (`s3:`, `sftp:`, `rest:`, `b2:`) need only their credentials.

Open `http://127.0.0.1:8080` (or put a TLS reverse proxy in front). After you create the administrator,
the **guided setup** walks through:

1. Connect the Restic repository. Access is checked and snapshots are listed immediately.
2. Pick an application template (or write a definition by hand).
3. Run the first test. If it fails, each check says what to do. A wrong `basePath` is detected and fixed in one click.
4. Schedule daily tests and add a notification destination (ntfy, email, webhook) under **Settings**.

Optional: once a run looks right, press **Trust this run as the baseline** on its inventory check. Later
runs then fail if files from it disappear (silent backup shrinkage).

### Why the data path must be identical

The worker asks the host's Docker daemon to bind-mount restored files into test containers, and the daemon
resolves those paths on the host. `RESTOREPROOF_HOST_DATA` is therefore mounted at the same path inside the
worker container.

## Without Docker (single user, development)

```bash
uv venv && uv pip install -e '.[postgres]'
export RESTOREPROOF_DATA_DIR=/var/lib/restoreproof    # SQLite by default; set RESTOREPROOF_DATABASE_URL for PostgreSQL
restoreproof worker &        # includes the scheduler
restoreproof serve --host 127.0.0.1 --port 8080
```

restic must be on `PATH`. Docker is needed only for database/application checks; without it those checks
report `error` and the run is `inconclusive`, never `passed`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RESTOREPROOF_DATA_DIR` | `./data` | reports, temporary restores, keys, SQLite DB |
| `RESTOREPROOF_DATABASE_URL` | SQLite in data dir | e.g. `postgresql+psycopg://user:pw@host/db` |
| `RESTOREPROOF_SECRET_KEY_FILE` | `$DATA/secrets/restoreproof.key` | credential encryption key (created if missing) |
| `RESTOREPROOF_SIGNING_KEY_FILE` | `$DATA/secrets/signing-ed25519.pem` | report signing key (created if missing) |
| `RESTOREPROOF_MAX_CONCURRENT_JOBS` | `1` | global concurrent attempts |
| `RESTOREPROOF_MIN_FREE_BYTES` | `1073741824` | refuse/abort restores that would cross this |
| `RESTOREPROOF_MAX_ATTEMPTS` | `2` | bounded retries for transient failures |
| `RESTOREPROOF_STALE_ATTEMPT_SECONDS` | `120` | heartbeat age after which an attempt is interrupted |
| `RESTOREPROOF_BASE_URL` | `http://localhost:8080` | used in notification links |
| `RESTOREPROOF_HTTP_PROBE_IMAGE` | `curlimages/curl:8.10.1` | image used for in-network HTTP checks |
| `RESTOREPROOF_AUTO_MIGRATE` | `true` | apply migrations on start (compose uses a `migrate` service) |

## Backups of RestoreProof itself

Back up the metadata database (`pg_dump`), `$DATA/reports`, and **separately** the two key files. Without
`restoreproof.key`, stored credentials cannot be decrypted. Without the signing key you can still verify old
reports, because the public key is embedded in each manifest, but you cannot sign new ones with the same identity.

## Upgrades

```bash
git pull && docker compose build && docker compose up -d     # the migrate service runs first
```

Migrations never alter or delete recovery evidence, and downgrading the initial schema is refused. Take a
`pg_dump` before upgrading.

## Operations

- `restoreproof reconcile` marks dead attempts and removes orphaned resources immediately (the worker also does this every minute).
- `docker ps -a --filter label=io.restoreproof.managed=true` lists test containers. Anything that remains belongs to a run marked `cleanup_failed`.
- `GET /api/v1/ready` checks database, schema, key, restore area and Docker.

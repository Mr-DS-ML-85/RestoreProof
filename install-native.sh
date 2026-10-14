#!/usr/bin/env bash
# RestoreProof native installer: Proxmox LXC, VMs or bare metal with systemd. No Docker required.
#
#   sudo ./install-native.sh                     # install + start (SQLite metadata, port 8080 on 127.0.0.1)
#   sudo ./install-native.sh --listen 0.0.0.0 --port 8080
#   sudo ./install-native.sh --podman            # Podman instead of Docker for database/app checks (experimental, untested)
#   sudo ./install-native.sh --no-systemd        # install files only (containers without systemd)
#
# Without Docker or Podman, file and SQLite checks still work; PostgreSQL and application checks report
# "could not run" (never a false pass). Safe to re-run: keys, config and data are never overwritten.
set -euo pipefail

PREFIX=/opt/restoreproof; DATA=/var/lib/restoreproof; ETC=/etc/restoreproof
LISTEN=127.0.0.1; PORT=8080; ENGINE=docker; SYSTEMD=1; START=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --listen) LISTEN="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --data) DATA="$2"; shift 2 ;;
    --podman) ENGINE=podman; shift ;;
    --no-systemd) SYSTEMD=0; shift ;;
    --no-start) START=0; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
SRC="$(cd "$(dirname "$0")" && pwd)"
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
PY=$(command -v python3 || true)
[[ -n "$PY" ]] || die "python3 is required (3.12 or newer)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || die "python 3.12+ required, found $("$PY" -V)"
"$PY" -c 'import venv, ensurepip' 2>/dev/null || die "python venv support missing (Debian/Ubuntu: apt install python3-venv)"
command -v restic >/dev/null || die "restic is required (Debian/Ubuntu: apt install restic; or https://restic.net)"
command -v "$ENGINE" >/dev/null || echo "    note: $ENGINE not found; database and application checks will report 'could not run'"
command -v rclone >/dev/null || echo "    note: rclone not found; SMB, FTP, WebDAV/Nextcloud and Google Drive destinations need it"

say "Creating the restoreproof system user"
id restoreproof >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin restoreproof
if [[ "$ENGINE" = docker ]] && getent group docker >/dev/null; then usermod -aG docker restoreproof; fi

say "Installing into $PREFIX"
install -d -m 0755 "$PREFIX"
install -d -m 0750 -o restoreproof -g restoreproof "$DATA"
install -d -m 0750 -o root -g restoreproof "$ETC"
[[ -x "$PREFIX/venv/bin/python" ]] || "$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet "$SRC[postgres]"

if [[ ! -f "$ETC/restoreproof.key" ]]; then
  say "Generating the credential-encryption key ($ETC/restoreproof.key)"
  (umask 027; head -c 32 /dev/urandom | base64 | tr '+/' '-_' > "$ETC/restoreproof.key")
  chown root:restoreproof "$ETC/restoreproof.key"; chmod 0640 "$ETC/restoreproof.key"
  echo "    Back this file up separately. Without it, stored passwords cannot be decrypted."
fi

if [[ ! -f "$ETC/restoreproof.env" ]]; then
  say "Writing $ETC/restoreproof.env"
  cat > "$ETC/restoreproof.env" <<EOF
# RestoreProof configuration (see docs/installation.md for every option).
RESTOREPROOF_DATA_DIR=$DATA
RESTOREPROOF_SECRET_KEY_FILE=$ETC/restoreproof.key
RESTOREPROOF_DOCKER_BINARY=$ENGINE
RESTOREPROOF_LISTEN=$LISTEN
RESTOREPROOF_PORT=$PORT
RESTOREPROOF_BASE_URL=http://$( [[ "$LISTEN" = 0.0.0.0 ]] && hostname -f || echo 127.0.0.1 ):$PORT
# SQLite is used by default. For PostgreSQL:
# RESTOREPROOF_DATABASE_URL=postgresql+psycopg://restoreproof:password@localhost/restoreproof
EOF
  chown root:restoreproof "$ETC/restoreproof.env"; chmod 0640 "$ETC/restoreproof.env"
fi

say "Applying database migrations"
runuser -u restoreproof -- env $(grep -v '^#' "$ETC/restoreproof.env" | xargs) "$PREFIX/venv/bin/restoreproof" migrate >/dev/null

if [[ $SYSTEMD -eq 1 ]]; then
  command -v systemctl >/dev/null || die "systemd not found; re-run with --no-systemd"
  say "Installing systemd units"
  install -m 0644 "$SRC/deploy/systemd/restoreproof-web.service" "$SRC/deploy/systemd/restoreproof-worker.service" /etc/systemd/system/
  if [[ "$DATA" != /var/lib/restoreproof ]]; then
    sed -i "s|ReadWritePaths=/var/lib/restoreproof|ReadWritePaths=$DATA|" /etc/systemd/system/restoreproof-*.service
  fi
  systemctl daemon-reload
  if [[ $START -eq 1 ]]; then
    systemctl enable restoreproof-web restoreproof-worker
    # restart (not just start) so a re-run after an upgrade really runs the new code
    systemctl restart restoreproof-web restoreproof-worker
    # Give the worker a moment to register before the health check looks for it.
    for _ in $(seq 1 15); do
      curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1 && break; sleep 1
    done
    sleep 3
  fi
fi

say "Checking the installation"
runuser -u restoreproof -- env $(grep -v '^#' "$ETC/restoreproof.env" | xargs) "$PREFIX/venv/bin/restoreproof" doctor || true

cat <<EOF

  RestoreProof is installed.  Dashboard: http://$LISTEN:$PORT
  Services: restoreproof-web, restoreproof-worker  (systemctl status restoreproof-worker)
  Config:   $ETC/restoreproof.env      Data: $DATA
  Local repositories or backup folders outside $DATA: allow them with
            systemctl edit restoreproof-worker   →   [Service] ReadWritePaths=/mnt/backups
EOF

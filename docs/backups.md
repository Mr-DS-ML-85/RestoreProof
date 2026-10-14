# Backups (optional module)

RestoreProof can test backups you already make, or make them too. Backups use restic and are stored in
standard restic repositories, so you can always restore with plain `restic`, even without RestoreProof.

**Safety boundary.** Recovery tests use a read-only restic allowlist and can never write. Only the backup
module may run `init`, `backup`, `forget` and `prune`, and `forget` and `prune` run only if you enable
retention on a plan.

## Destinations

| Type | Use it for | Credentials (stored encrypted) | Needs |
|---|---|---|---|
| `local` | internal disk, USB drive, mounted NAS/NFS | none | |
| `sftp` | **another Linux server** or NAS over SSH (SFTP/SCP) | SSH private key; host key pinned | `ssh` |
| `smb` | Windows shares, Synology, QNAP, TrueNAS, Unraid, OMV | password | `rclone` |
| `webdav` | Nextcloud, ownCloud, Synology WebDAV, generic | password (Nextcloud: an app password) | `rclone` |
| `ftp` | FTP / FTPS servers | password | `rclone` |
| `rest` | restic `rest-server` over HTTP/HTTPS | optional username + password | |
| `s3` | AWS, MinIO, Wasabi, Garage, Backblaze S3 | access key + secret | |
| `b2` | Backblaze B2 native | account id + key | |
| `gdrive` | Google Drive | OAuth token from `rclone authorize "drive"` | `rclone` |

The Docker image includes restic, rclone and ssh. For native installs, install `rclone` if you use
SMB/WebDAV/FTP/Google Drive.

Every new destination gets a **randomly generated repository password, shown once**. Store it in a
password manager. It is the only way to decrypt the backups if this RestoreProof installation is lost.

For SFTP, press **Fetch** to read the server's host key, compare the `SHA256:` fingerprint with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server, then save. A changed host key (for
example a man-in-the-middle) makes the backup fail instead of connecting.

## Plans: local first, never a full disk

A plan lists **destinations in order of preference**. For each backup:

1. Consistency hooks run (below). If one fails, nothing is backed up, and the previous good backup is untouched.
2. RestoreProof measures what will be backed up.
3. It walks the destination list and takes **the first one that fits**:
   - **Local destination:** used only if `free space − expected new data ≥ reserve`, where the reserve is
     `max(min_free_percent of the disk, RESTOREPROOF_MIN_FREE_BYTES)`. The expected new data is the full
     size on the first backup, then about twice the recent growth.
   - **Any destination:** the repository must open. Repositories RestoreProof created are initialised on first use.
4. The run records a verdict for every destination ("usb: not enough space: needs ~42 GB, 30 GB free, must
   keep 50 GB free" → "nas-sftp: chosen").
5. If nothing fits, the run is `blocked` and nothing is written anywhere.

Typical setup: `[usb-disk, nas-smb, offsite-b2]`. The fast local disk is used while it has room, the NAS
takes over when it's full, and the cloud is the last resort.

## Consistency hooks

Backing up a database file while the app writes to it can give you a backup that won't restore.

```json
[
  {"type": "sqlite_backup", "source": "/srv/vaultwarden/db.sqlite3", "output": "/srv/vaultwarden/backup/db.sqlite3"},
  {"type": "postgres_dump", "container": "nextcloud-db", "user": "nextcloud", "database": "nextcloud",
   "output": "/srv/nextcloud/db/dump.sql", "gzip": false},
  {"type": "pause_container", "container": "paperless"}
]
```

- `sqlite_backup` uses SQLite's online-backup API, so the copy is consistent even while the app is running. It is checked with `quick_check`.
- `postgres_dump` streams `pg_dump` from the container. A failed or empty dump never replaces the previous one.
- `pause_container` freezes the container during the snapshot and always unpauses it afterwards, even if the backup fails or the worker restarts.
- Hook outputs must lie inside a backed-up folder, and the plan is rejected otherwise. There is no free-form shell hook.

## Results

| Status | Meaning |
|---|---|
| `succeeded` | snapshot written, every file read |
| `partial` | snapshot written, but **some files could not be read**; they are named, and you are alerted |
| `failed` | nothing usable was written (hook failed, repository error, crash) |
| `blocked` | no destination could take the backup (space, reachability) |

## Retention

Off by default. When enabled, `forget --keep-daily/weekly/monthly/yearly` applies **only to snapshots made by
that plan** (they carry a `rp-plan-…` tag). `prune` waits if a recovery test is reading the same repository.

## Verify after backup

Select recovery tests on the plan. After each successful backup, the tests that read *that* destination are
queued automatically, so you learn the same night whether the new snapshot actually restores.

## Deployment notes

- **Docker:** mount the folders to back up into the `worker` (read-only is fine), and local destinations
  read-write, at the same paths.
- **systemd:** the worker can read the whole filesystem (`ProtectHome=read-only`). Allow writing to local
  destinations with `systemctl edit restoreproof-worker` → `[Service] ReadWritePaths=/mnt/usb`.
- Backups run at low CPU and I/O priority and count towards `RESTOREPROOF_MAX_CONCURRENT_JOBS`.

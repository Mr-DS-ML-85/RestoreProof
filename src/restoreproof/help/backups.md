# Backups

Already making restic backups? You don't need this page: connect them under **Sources**.

No backups yet? RestoreProof can make them for you, and then prove they restore.

## 1. Add a destination (where backups go)

**Backups → Add a destination.** Choose a type:

| Type | When to use it |
|---|---|
| This machine | a second disk, a USB drive, or a NAS folder that's already mounted |
| Another Linux server over SSH (SFTP/SCP) | a Raspberry Pi, VPS or NAS you can `ssh` into |
| SMB share | Synology, QNAP, TrueNAS, Unraid, or a Windows share |
| WebDAV / Nextcloud | a Nextcloud folder (use an *app password*) |
| FTP / FTPS | an FTP server |
| restic REST server | `rest-server` on another machine |
| S3 / Backblaze B2 | cloud storage (AWS, Wasabi, MinIO, Backblaze) |
| Google Drive | your Drive; get the token with `rclone authorize "drive"` |

For **SFTP**, press **Fetch** to read the server's fingerprint and compare it with the server before
saving. This protects you from connecting to the wrong machine.

When the destination is created you'll see a **repository password, once**. Save it in a password manager.
It's the only way to read these backups without RestoreProof.

## 2. Make a plan (what to back up)

**Backups → New backup plan.**

1. **Folders to back up**: one per line, for example `/srv/vaultwarden`.
2. **Destinations, in order**: tick one or more. RestoreProof uses the **first one that fits**.
3. **Keep at least this much of a local disk free**: default 10%. If a local disk would get fuller than
   that, the backup goes to the next destination instead. Your disk never fills up.
4. **Make databases consistent** (recommended for apps with a database): see below.
5. **Retention**: how many daily, weekly and monthly backups to keep. Off by default.
6. **After each backup, run these recovery tests**: tick the tests that read this destination.
7. Tick **Run on schedule** and save.

Press **Back up now** to try it. The run shows where the backup went and why, for example:

> usb-disk: not enough space, needs ~42 GB, 30 GB free, must keep 50 GB free
> nas-sftp: **chosen**

## 3. Make databases consistent

Copying a database file while the app is writing to it can give you a backup that doesn't restore. Add a
step that runs before each backup:

```json
[
  {"type": "sqlite_backup", "source": "/srv/vaultwarden/db.sqlite3", "output": "/srv/vaultwarden/backup/db.sqlite3"},
  {"type": "postgres_dump", "container": "nextcloud-db", "user": "nextcloud", "database": "nextcloud", "output": "/srv/nextcloud/db/dump.sql"},
  {"type": "pause_container", "container": "paperless"}
]
```

- **sqlite_backup**: a safe copy even while the app runs.
- **postgres_dump**: a dump from your database container.
- **pause_container**: freezes the container for the few seconds of the snapshot.

The output must be inside a folder you back up. If a step fails, nothing is backed up, and your previous
backup stays as it was.

## Results

- **succeeded**: all good.
- **partial**: the backup was saved, but some files couldn't be read (they're listed). Fix the permissions.
- **failed** / **blocked**: nothing usable was written; the message says why.

## Running in Docker or LXC

- **Docker:** add the folders to back up, and any local destination, to the `worker` service in
  `compose.yaml` (the examples are already there, commented out).
- **systemd/LXC:** to let RestoreProof write to a local folder, run `sudo systemctl edit restoreproof-worker` and add:

```
[Service]
ReadWritePaths=/mnt/usb
```

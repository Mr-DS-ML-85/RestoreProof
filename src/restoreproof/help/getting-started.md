# Getting started

RestoreProof answers one question: **"If my server died today, could I get my apps back from my backups?"**

It does this by actually trying. It takes your backup, restores it into a sealed-off sandbox (never on top of
your real data), checks that the files, databases and apps really work, and then deletes the sandbox. You get
a clear result: **passed**, or **failed with what to fix**.

## What you need

- A Linux computer or server. A Raspberry Pi 4/5 works.
- **Docker**, or any Linux with systemd (Proxmox LXC containers are fine).
- Backups made with **restic**. No backups yet? RestoreProof can make them for you, see [Backups](#/help/backups).

## Step 1: Install

With Docker:

```
git clone <the RestoreProof repository> restoreproof
cd restoreproof
./install.sh
```

Without Docker (LXC, VM or bare metal):

```
sudo apt install python3 python3-venv restic
git clone <the RestoreProof repository> restoreproof
cd restoreproof
sudo ./install-native.sh
```

Then open **http://127.0.0.1:8080** in your browser.

## Step 2: Create your account

The first page asks for an email and a password (at least 12 characters). This becomes the administrator
account.

## Step 3: Try it with demo data (1 minute)

Not sure where to start? On the **Getting started** page, press **Try it with demo data**.

RestoreProof creates a tiny pretend app (5 notes, a settings file and a small database), makes a real
backup of it, and tests it. After about 10 seconds you'll see **passed**, with every check in green.

Then press **Break the demo**. This simulates a bad backup (two notes lost, the database damaged). Run the
test again: it **fails**, and each red line tells you what went wrong and what to do. That's exactly what you
would see if one of your real backups broke.

When you're done, delete the demo app on its page (Danger zone).

## Step 4: Connect your own backup

1. Go to **Sources** (or follow the Getting started steps).
2. Enter a name, the **repository** (where your restic backups are, for example `/mnt/backups/restic`,
   `sftp:user@nas:/backups` or `s3:s3.amazonaws.com/my-bucket`) and the **repository password**.
3. Press **Connect & check access**. You should see "Connected. 12 snapshot(s) found".

> The password is stored encrypted. RestoreProof only *reads* your backups. It can never delete or change them.

## Step 5: Pick what to protect

1. Go to **Applications → Protect an application**.
2. Pick your app (Vaultwarden, Nextcloud, WordPress, Home Assistant…). Don't see yours? Pick **Generic files**.
3. Open **Browse your backup** and click through the folders until you see your app's files. Press
   **Use this folder as the app folder**.
4. For Generic files, click **must exist** next to files that matter (a config file, a database) and
   **must not be empty** next to important folders.
5. Press **Create & run first test**.

## Step 6: Read the result

- **Passed** (green): your backup restored and every check worked.
- **Failed** (red): open the run. Every failed check has a blue **What to do next** box. Often there's a
  one-click fix, such as "Set basePath to `srv/app` & re-run".
- **Inconclusive** (yellow): something stopped the test from finishing (for example the backup server was
  offline). It is retried automatically.

## Step 7: Make it automatic

1. On the app's page, under **Schedule**, tick **Scheduled tests enabled** (for example every night at 03:00).
2. Under **Settings → Notifications**, add where you want alerts (ntfy, email or a webhook) and press **Send test**.

That's it. RestoreProof now tests your backup every night and tells you the moment a restore would fail.

## Where to go next

- [Writing a test](#/help/writing-tests): every check explained, with examples.
- [Templates](#/help/templates): make your own app templates, and share or import them.
- [Backups](#/help/backups): let RestoreProof make the backups too.
- [When a test fails](#/help/troubleshooting): the most common problems and fixes.

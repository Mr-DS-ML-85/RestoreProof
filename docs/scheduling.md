# Scheduling semantics

## Who runs the schedule?

RestoreProof has its **own scheduler**. It does not rely on cron, systemd timers or restic. The scheduler runs
inside `restoreproof worker` (default) or as a separate `restoreproof scheduler` process (the compose
`scheduler` service). It ticks every 30 seconds.

Each application has one policy, holding a **cron expression** plus a **time zone** (for example `0 3 * * *` in
`Europe/Berlin`), with optional random **jitter** to spread expensive tests. The next run time is **stored in
the database**, so restarts never forget a slot or fire it twice.

## What happens at a slot

1. The scheduler creates a job with the idempotency key `sched:<policy>:<slot>`. A second scheduler, or a
   repeated tick for the same slot, finds that key and creates nothing.
2. The job waits in the queue until a worker picks it up. Claiming is atomic, so two workers can never take
   the same job.
3. If a maintenance window is configured, a scheduled job waits for the window to open. Manual tests ignore the window.
4. If the host is busy (load above the configured limit), the worker waits before starting new tests (see
   [Protecting production](#protecting-production)).

## Overlaps

**At most one test per application is active at a time.** This is enforced by a unique constraint in the database.
- A scheduled slot that arrives while the previous test of that app is still running is **skipped**, not queued
  behind it. The skip is written to the audit log (`schedule.skipped_overlap`).
- A manual "Test now" while one is running returns `409 job_already_active` with the running job's ID.
- Different applications can run at the same time, up to `RESTOREPROOF_MAX_CONCURRENT_JOBS` (default **1**, so
  tests run one after another).

## Missed runs (downtime)

If RestoreProof was down across several slots, **only one** catch-up run is created when it comes back, and the
next slot is computed from *now*. You never get a burst of N missed tests.

## Retries

| Outcome | Retried? |
|---|---|
| `failed`: a check showed the backup is not recoverable | **No.** This is a real result, so you get alerted. |
| `timed_out`, `blocked` (budget, disk), `cancelled` | No |
| `inconclusive` from a **transient** problem (repository unreachable or locked) | Yes, as a new attempt after 30 s, then 60 s, 120 s … (max 15 min), up to `RESTOREPROOF_MAX_ATTEMPTS` (default 2) |
| Worker crashed or host rebooted mid-test (`interrupted`) | Yes, same bounded policy, after its resources are cleaned up |

Every attempt is stored separately, so a retry never hides the earlier failure. When retries run out, the
job ends `inconclusive`, which is never reported as a pass.

## Overdue and alerts

`max_age_last_success_hours` (default 48) sets how old the last *passing* test may be before the app is
**overdue**. The scheduler sends `test_overdue` once per period, and `worker_offline` only when no worker is
running at all.

## Protecting production

Most homelabs test on the same machine that runs production. By default RestoreProof is a polite neighbour:

| Setting | Default | Effect |
|---|---|---|
| `spec.restore.priority` | `low` | restic runs under `nice -n 19` and `ionice -c 3` (idle I/O class), so it only gets disk time production isn't using |
| `spec.restore.limitDownloadKiB` | none | caps restic's read bandwidth from the repository (`--limit-download`) |
| container `limits` | 512 MB, 1 CPU, CPU weight 256 | test databases and apps can't take over the host; `limits.ioWeight` (10–1000) adds a block-I/O weight where the kernel supports it |
| Settings → Workload → *Pause when load is above* | 1.5 × CPUs | the worker waits for the 1-minute load average to drop before starting a test |
| Settings → Workload → *Maintenance window* | none | e.g. `01:00-06:00`: scheduled tests only start inside the window |
| `spec.restore.maxBytes` / free-space guard | | refuses or stops restores that would fill the disk |

For large restores (100 GB+), the cleanest option is a **separate test machine**. Run `restoreproof worker` on
any other host with access to the same database and repositories, and stop the worker on the production host.

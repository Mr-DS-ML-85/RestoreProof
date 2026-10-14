# Architecture

```
 Dashboard / API clients
          │  bearer tokens, RBAC (viewer < operator < admin)
          ▼
   FastAPI  (web) ── validates input, creates jobs (202), never runs restores in a request
          │
          ▼
   Metadata DB (PostgreSQL; SQLite for dev) ── durable job state, evidence index, audit trail
      ▲        ▲
      │        └── scheduler: cron per app → idempotent job creation, overdue / worker-offline alerts
      │
   worker ── claim job (compare-and-swap) → new attempt row → AttemptRunner
               │  heartbeat thread, cancellation flag, deadline
               ├── ResticAdapter  (allowlisted subcommands, argv arrays, timeouts)
               ├── run-<attempt>/restore   (marker-owned, unique per attempt)
               ├── DockerEnvironment: --internal network, postgres + app containers, curl probe
               ├── checks: files / postgres / http → CheckResult rows committed immediately
               ├── evidence: run.log → cleanup → manifest.json (hash + signature) → report.html
               └── notifications
```

## Job state machine

```
queued ──claim──▶ running ──▶ passed | failed | inconclusive | timed_out | cancelled | blocked
   │                 │
   └─cancel─▶ cancelled      └─(transient failure or interrupted attempt, attempts < MAX)──▶ queued (retry)
```

Attempts: `running → passed | failed | inconclusive | timed_out | cancelled | blocked | interrupted`.
Cleanup is tracked separately: `pending → completed | cleanup_failed | not_required`, and `cleanup_failed`
can later become `completed` through reconciliation.

All transitions are checked in `jobs/state_machine.py`, and every allowed and forbidden transition has a unit test.

## Aggregation rule

1. Any required check `failed` → `failed`
2. Otherwise, any required check `error`/`skipped` → `inconclusive`
3. Otherwise, no required check `passed` → `inconclusive`
4. Otherwise → `passed`

Advisory checks (`required: false`, e.g. RPO/RTO) are reported but never decide the outcome. A definite failure
observed before a later infrastructure error keeps the run `failed`.

## Concurrency and durability

- `jobs.active_lock` is unique and equals the app id while a job is non-terminal, so no two active jobs can exist for one app.
- `jobs.idempotency_key` is unique. Scheduler slots use `sched:<policy>:<slot>`; manual requests can pass `Idempotency-Key`.
- Claiming uses an `UPDATE … WHERE status='queued'` with a row-count check, which is safe across processes.
- Workers heartbeat every few seconds. An attempt whose heartbeat is older than `STALE_ATTEMPT_SECONDS` is
  marked `interrupted` by any worker's reconciler, its resources are cleaned up, and the job is retried or closed as `inconclusive`.
- Missed schedule slots after downtime collapse into a single run.
- Migrations are serialized with a file lock and a PostgreSQL advisory lock.

## Why the API never sees restored data

In the compose deployment, `web` mounts only the reports directory, read-only. The temporary restore area and the
Docker socket are mounted only into `worker`.

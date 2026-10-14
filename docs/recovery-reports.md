# Recovery reports and evidence

Each attempt writes the following to `$DATA/reports/<job_id>/attempt-<n>/`:

| File | Content |
|---|---|
| `run.log` | sanitized restic and docker command output, written **before** cleanup |
| `manifest.json` | machine-readable result (schema below), sealed |
| `report.html` | human-readable rendering of the sealed manifest |

Each file's SHA-256 is recorded in `evidence_artifacts`. Check results are also stored row by row in the database
as soon as they are known, so a crash still leaves partial evidence.

## Manifest (schema_version 1.0)

Top-level keys: `schema_version`, `restoreproof_version`, `run_id` (attempt id), `job_id`, `attempt_number`,
`trigger`, `application`, `source`, `definition` (version + SHA-256 of the exact YAML that ran),
`recovery_point` (adapter, immutable `native_id`, `timestamp`, `hostname`, `paths`, selection policy and reason),
`tool_version`, `adapter_guarantees`, `isolation`, `started_at`, `finished_at`, `restore` (files, bytes),
`result` (`status`, `reason`, `error_code`, counts), `layers` (status per layer), `checks[]`, `timings_ms`,
`stages[]`, `cleanup` (`status`, `orphaned_resources`, `problems[]`), `evidence`.

## Canonical form and hashing

1. Remove `evidence.manifest_sha256` and `evidence.signature`.
2. Serialize as JSON with UTF-8 encoding, keys sorted, separators `,` and `:`, and no extra whitespace
   (Python: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`).
3. SHA-256 of those bytes → `evidence.manifest_sha256`.
4. Ed25519 signature over the 32 raw digest bytes → `evidence.signature` (`value`, `public_key`,
   `public_key_fingerprint` = first 32 hex characters of SHA-256 of the raw public key).

```bash
restoreproof verify-report manifest.json --fingerprint <expected fingerprint>
# exit 0: hash ok and signature valid; 2: tampered, invalid, or signed by an unexpected key
```

The API endpoint `GET /api/v1/jobs/{id}/report` returns the manifest together with its verification result.

## What evidence does and does not prove

A valid hash shows the document has not changed since it was sealed. A valid signature shows it was sealed by the
holder of that key. Neither proves the checks were the right ones: read `definition`, `checks` and
`adapter_guarantees` to see exactly what was verified. Reports are never edited after the fact, and a re-run
produces a new attempt or job.

Reports contain hashes, counts and sanitized messages, never file contents or database rows.

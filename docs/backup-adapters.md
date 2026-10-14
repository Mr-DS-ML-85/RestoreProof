# Backup adapters

Adapters implement `adapters/base.py::BackupAdapter`:

| Operation | Purpose |
|---|---|
| `validate_credentials()` | open the repository with the configured credentials |
| `list_recovery_points()` | all snapshots with immutable IDs and timestamps |
| `get_recovery_point_metadata(id)` | one snapshot |
| `estimate_restore_size(id)` | used for the pre-flight storage budget |
| `check_repository(read_data_subset)` | tool-native integrity check |
| `restore_to_destination(id, dest, include)` | extract into a RestoreProof-owned directory |
| cancellation | via the `poll` hook, which kills the process group |

Every adapter must declare `guarantees`, a plain statement of what each operation does and does not establish.
These statements are copied into every report.

## Restic (v0.1)

- Read-only subcommand allowlist: `version`, `cat`, `snapshots`, `stats`, `check`, `restore`.
- `RESTIC_PASSWORD_FILE` points at a 0600 file in `/dev/shm`. Backend variables are limited to a known allowlist
  (`AWS_*`, `B2_*`, `AZURE_*`, `GOOGLE_*`, `RESTIC_REST_*`, `OS_*`).
- `restore --verify` re-reads restored files and compares them with the snapshot. This proves the files match what
  was backed up, **not** that what was backed up was correct. Use `file_hash`/`hash_manifest` with independently
  produced hashes for that.
- `check` without `readDataSubset` verifies structure only. `readDataSubset: "5%"` (or `"1/10"`, `"500M"`) reads and
  verifies that portion of pack data. Run full reads separately and rarely: they read the whole repository.
- Exit codes 10/11/12 (repository missing / locked / wrong password, restic ≥ 0.17) are classified. Unreachable or
  locked repositories count as transient (`inconclusive`, retried). A wrong password counts as a definite failure.

## Adding Kopia or Borg

1. Implement `BackupAdapter` with an allowlist of read-only subcommands.
2. State the real verification guarantees. For example, Kopia's `snapshot verify` without `--verify-files-percent`
   does not read all file content.
3. Register it in `build_adapter()` and add it to `SourceSpec.adapter` in `definitions.py`.
4. Add integration tests modelled on `tests/integration/test_failure_matrix.py` with a real repository.

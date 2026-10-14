# Threat model

RestoreProof handles backup credentials and recovered data, which may include personal data and secrets.
Restored applications and images are treated as **untrusted**.

| Threat | Control | Where |
|---|---|---|
| Routine test damages production | restic subcommand allowlist (`version cat snapshots stats check restore`); `--no-lock` for reads; restores only into a new marker-owned directory | `adapters/restic.py`, `security/paths.py` |
| Command / flag injection | argv arrays only, executable allowlist, snapshot IDs must be hex, include patterns and repository strings may not start with `-`, `--` separators | `security/process.py`, `adapters/restic.py` |
| Path traversal / symlink escape | relative paths only, no `..`, symlinks rejected while resolving, final path must stay inside the root | `security/paths.py` |
| Cleanup deletes host data | deletion only of `temp_root/run-<uuid>` directories whose marker file names the same attempt; `rmtree` unlinks symlinks without following them | `security/paths.py`, tests `test_cleanup_refuses_paths_outside_temp_root` |
| Restored app reaches production or the internet | per-attempt `docker network create --internal`, no published ports, no host network | `runner/docker.py` |
| Container breakout | `--cap-drop ALL` + small allowlist, `no-new-privileges`, PID/memory/CPU limits, no privileged mode, never the Docker socket, mount sources restricted to the attempt directory | `runner/docker.py`, `definitions.py` |
| Malicious SQL in a test definition | single `SELECT`/`WITH` statement, run as `rp_verifier` (`pg_read_all_data` only) with `default_transaction_read_only=on` and `statement_timeout` | `checks/postgres.py` |
| Credential theft from the DB | Fernet encryption, key file outside the DB (Docker secret in compose), credentials write-only in the API | `security/crypto.py`, `api/schemas.py` |
| Secrets in logs/reports | known-secret replacement plus pattern redaction (URL credentials, bearer tokens, key=value, AWS keys, PEM keys), applied before persistence | `evidence/sanitization.py`, test `test_wrong_password_fails_without_leaking_secret` |
| Password on disk after a crash | the restic password file goes to `/dev/shm` (0600, deleted after use) and is never passed in argv | `adapters/restic.py` |
| Report tampering | canonical JSON + SHA-256 + Ed25519 signature. Old reports are never rewritten | `evidence/manifest.py` |
| Compromised or careless admin | append-only audit trail of sources, credentials (never values), definitions (versioned), policies and logins. RBAC limits config changes to admins | `audit.py` |
| Brute-force login | scrypt hashes, per-IP and per-account rate limiting, 12-char minimum | `auth/security.py` |
| XSS in the dashboard | all API data is escaped, strict CSP (`script-src 'self'`), report HTML served with `default-src 'none'` | `static/app.js`, `main.py` |

## Known limits

- **The worker holds Docker socket access, which is root-equivalent on its host.** Run the worker on a
  dedicated VM or host for anything you do not trust. A container is not a strong security boundary for hostile code.
- Hashes and signatures prove a report is unchanged. They do not prove the test itself was honest. For higher
  assurance, copy reports to append-only storage on another system and keep the signing-key fingerprint elsewhere.
- **Key management: if `restoreproof.key` is lost, stored credentials cannot be recovered.** Re-enter them.
  Back the key up separately from the database backup.
- The login rate limiter is in-process. Put a reverse proxy with rate limiting in front if you expose the UI.
- Bearer tokens live in `sessionStorage` (no cookies, so no CSRF surface). Serve the UI over TLS.

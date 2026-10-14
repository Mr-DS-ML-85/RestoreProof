"""Credential encryption at rest.

The Fernet key lives in a file outside the metadata database (RESTOREPROOF_SECRET_KEY_FILE, ideally a Docker
secret). Losing that file makes stored credentials unrecoverable: back it up separately (docs/threat-model.md).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from restoreproof.config import get_settings
from restoreproof.db.models import StoredSecret


class SecretUnavailable(Exception):
    pass


def load_or_create_key(path: Path) -> bytes:
    if path.exists():
        key = path.read_bytes().strip()
    else:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = Fernet.generate_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    Fernet(key)  # validates format
    return key


def _fernet() -> tuple[Fernet, str]:
    key = load_or_create_key(get_settings().secret_key_file)
    return Fernet(key), hashlib.sha256(key).hexdigest()[:16]


def store_secret(session: Session, values: dict[str, Any], existing_ref: str | None = None) -> str:
    f, fp = _fernet()
    token = f.encrypt(json.dumps(values).encode()).decode()
    if existing_ref:
        row = session.get(StoredSecret, existing_ref)
        if row is not None:
            row.ciphertext, row.key_fingerprint = token, fp
            return row.id
    row = StoredSecret(ciphertext=token, key_fingerprint=fp)
    session.add(row)
    session.flush()
    return row.id


def load_secret(session: Session, ref: str | None) -> dict[str, Any]:
    if not ref:
        return {}
    row = session.get(StoredSecret, ref)
    if row is None:
        raise SecretUnavailable("referenced secret does not exist")
    f, _ = _fernet()
    try:
        return json.loads(f.decrypt(row.ciphertext.encode()))
    except InvalidToken as exc:
        raise SecretUnavailable("stored secret cannot be decrypted with the configured key") from exc

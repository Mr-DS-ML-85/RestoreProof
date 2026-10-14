"""Evidence manifest: canonical serialization, hashing and optional Ed25519 signing.

Canonical form (documented in docs/recovery-reports.md): JSON, UTF-8, keys sorted, separators (",", ":"),
no insignificant whitespace, with `evidence.manifest_sha256` and `evidence.signature` removed before hashing.

A hash proves the document is unchanged since hashing. It does not prove the test was honest; a signature
additionally ties it to whoever holds the signing key.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

SCHEMA_VERSION = "1.0"


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _hash_input(manifest: dict[str, Any]) -> dict[str, Any]:
    m = copy.deepcopy(manifest)
    ev = m.get("evidence") or {}
    ev.pop("manifest_sha256", None)
    ev.pop("signature", None)
    m["evidence"] = ev
    return m


def manifest_hash(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(_hash_input(manifest))).hexdigest()


def _load_signing_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("signing key is not Ed25519")
        return key
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return key


def public_key_info(pub: Ed25519PublicKey) -> tuple[str, str]:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()[:32]


def seal(manifest: dict[str, Any], signing_key_file: Path | None) -> dict[str, Any]:
    """Add manifest_sha256 (and a signature if a key path is given). Returns the sealed manifest."""
    sealed = copy.deepcopy(manifest)
    digest = manifest_hash(sealed)
    sealed.setdefault("evidence", {})["manifest_sha256"] = digest
    if signing_key_file is not None:
        key = _load_signing_key(signing_key_file)
        pub_b64, fp = public_key_info(key.public_key())
        sig = key.sign(bytes.fromhex(digest))
        sealed["evidence"]["signature"] = {"algorithm": "ed25519", "signed": "manifest_sha256",
                                           "value": base64.b64encode(sig).decode(),
                                           "public_key": pub_b64, "public_key_fingerprint": fp}
    return sealed


def verify(manifest: dict[str, Any], trusted_fingerprint: str | None = None) -> dict[str, Any]:
    ev = manifest.get("evidence") or {}
    claimed = ev.get("manifest_sha256")
    actual = manifest_hash(manifest)
    out: dict[str, Any] = {"hash_ok": claimed == actual, "claimed": claimed, "actual": actual,
                           "signature": "absent"}
    sig = ev.get("signature")
    if sig:
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"]))
            pub.verify(base64.b64decode(sig["value"]), bytes.fromhex(actual))
            _, fp = public_key_info(pub)
            out["signature"] = "valid"
            out["public_key_fingerprint"] = fp
            if trusted_fingerprint and fp != trusted_fingerprint:
                out["signature"] = "valid_but_untrusted_key"
        except (InvalidSignature, KeyError, ValueError):
            out["signature"] = "invalid"
    return out

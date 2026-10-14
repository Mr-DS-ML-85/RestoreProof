"""Backup destinations: where a restic repository lives, described per protocol.

Native restic backends: local disk, SFTP/SCP (any Linux server over SSH), REST server (HTTP/HTTPS), S3 and
compatibles (MinIO, Wasabi, Garage, Backblaze S3), Backblaze B2. Through rclone (configured purely with
environment variables, no rclone.conf): SMB/CIFS (Windows shares, most NAS), FTP/FTPS, WebDAV (Nextcloud,
ownCloud, Synology, generic) and Google Drive.

Secrets never appear in argv: they go into RESTIC_*/AWS_*/RCLONE_CONFIG_* environment variables or into
0600 files inside the adapter's private temp directory.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

HOST_RE = r"^[A-Za-z0-9.-]{1,253}$|^\[[0-9a-fA-F:]+\]$"
USER_RE = r"^[A-Za-z0-9._@\\-]{1,128}$"
PATH_RE = r"^[^\x00\n]{0,1024}$"
RCLONE_REMOTE = "RPDEST"  # env-configured rclone remote name (RCLONE_CONFIG_RPDEST_*)


class _Loc(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Local(_Loc):
    """A folder on this machine: an internal disk, USB drive or mounted NAS/NFS share."""

    type: Literal["local"]
    path: str = Field(pattern=r"^/[^\x00\n]{1,1023}$")

    @field_validator("path")
    @classmethod
    def _no_traversal(cls, v: str) -> str:
        if ".." in Path(v).parts:
            raise ValueError("path may not contain '..'")
        return v.rstrip("/") or "/"


class Sftp(_Loc):
    """Another Linux server (or NAS) over SSH. Key-based authentication, host key pinned."""

    type: Literal["sftp"]
    host: str = Field(pattern=HOST_RE)
    port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(pattern=USER_RE)
    path: str = Field(pattern=r"^/[^\x00\n]{0,1023}$")
    # "ssh-ed25519 AAAA..." as printed by `ssh-keyscan`; required so a man-in-the-middle cannot be accepted.
    host_key: str = Field(pattern=r"^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]{20,}$")


class Rest(_Loc):
    """restic REST server (rest-server), over HTTP or HTTPS."""

    type: Literal["rest"]
    url: str = Field(pattern=r"^https?://[^\s@]+$")


class S3(_Loc):
    type: Literal["s3"]
    endpoint: str = Field(pattern=r"^(https?://)?[A-Za-z0-9.-]+(:\d+)?$")
    bucket: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,62}$")
    prefix: str = Field(default="", pattern=r"^[A-Za-z0-9._/-]{0,512}$")
    region: str = Field(default="", pattern=r"^[a-z0-9-]{0,40}$")


class B2(_Loc):
    type: Literal["b2"]
    bucket: str = Field(pattern=r"^[A-Za-z0-9-]{6,50}$")
    prefix: str = Field(default="", pattern=r"^[A-Za-z0-9._/-]{0,512}$")


class Smb(_Loc):
    """SMB/CIFS share: Windows, Synology, QNAP, TrueNAS, Unraid, OpenMediaVault..."""

    type: Literal["smb"]
    host: str = Field(pattern=HOST_RE)
    port: int = Field(default=445, ge=1, le=65535)
    share: str = Field(pattern=r"^[A-Za-z0-9._$ -]{1,80}$")
    path: str = Field(default="restoreproof", pattern=r"^[A-Za-z0-9._/ -]{0,512}$")
    user: str = Field(pattern=USER_RE)
    domain: str = Field(default="WORKGROUP", pattern=r"^[A-Za-z0-9.-]{1,64}$")


class Ftp(_Loc):
    type: Literal["ftp"]
    host: str = Field(pattern=HOST_RE)
    port: int = Field(default=21, ge=1, le=65535)
    user: str = Field(pattern=USER_RE)
    path: str = Field(default="restoreproof", pattern=r"^[A-Za-z0-9._/ -]{0,512}$")
    tls: Literal["explicit", "implicit", "none"] = "explicit"


class WebDav(_Loc):
    """WebDAV, including Nextcloud/ownCloud (https://host/remote.php/dav/files/USER) and Synology."""

    type: Literal["webdav"]
    url: str = Field(pattern=r"^https?://[^\s@]+$")
    vendor: Literal["nextcloud", "owncloud", "other"] = "other"
    user: str = Field(pattern=USER_RE)
    path: str = Field(default="restoreproof", pattern=r"^[A-Za-z0-9._/ -]{0,512}$")


class GoogleDrive(_Loc):
    """Google Drive. The OAuth token comes from `rclone authorize "drive"` on any machine with a browser."""

    type: Literal["gdrive"]
    path: str = Field(default="restoreproof", pattern=r"^[A-Za-z0-9._/ -]{0,512}$")
    root_folder_id: str = Field(default="", pattern=r"^[A-Za-z0-9_-]{0,128}$")


Location = Annotated[Union[Local, Sftp, Rest, S3, B2, Smb, Ftp, WebDav, GoogleDrive], Field(discriminator="type")]
LOCATION = TypeAdapter(Location)
RCLONE_TYPES = {"smb", "ftp", "webdav", "gdrive"}

# Secret fields each location type accepts (stored encrypted; never returned by the API).
SECRET_FIELDS: dict[str, set[str]] = {
    "local": set(), "sftp": {"private_key"}, "rest": {"username", "password"},
    "s3": {"access_key", "secret_key"}, "b2": {"account_id", "account_key"},
    "smb": {"password"}, "ftp": {"password"}, "webdav": {"password"}, "gdrive": {"token"},
}


def scan_host_keys(host: str, port: int, timeout: int = 10) -> list[dict[str, str]]:
    """Fetch an SSH server's host keys so the user can confirm the fingerprint (trust on first use, but
    explicitly). Returns [{"key": "ssh-ed25519 AAAA...", "fingerprint": "SHA256:..."}]."""
    import base64
    import hashlib
    import subprocess

    if not re.match(HOST_RE, host) or not (1 <= port <= 65535):
        raise ValueError("invalid host or port")
    r = subprocess.run(["ssh-keyscan", "-T", str(timeout), "-t", "ed25519,ecdsa,rsa", "-p", str(port), "--", host],
                       capture_output=True, text=True, timeout=timeout + 10)
    out = []
    for line in r.stdout.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        blob = base64.b64decode(parts[2])
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        out.append({"key": f"{parts[1]} {parts[2]}", "fingerprint": fp})
    order = {"ssh-ed25519": 0}
    return sorted(out, key=lambda k: order.get(k["key"].split()[0], 1))


def parse(data: dict[str, Any]) -> Any:
    return LOCATION.validate_python(data)


def describe(loc: Any) -> str:
    t = loc.type
    if t == "local":
        return f"local folder {loc.path}"
    if t == "sftp":
        return f"SFTP {loc.user}@{loc.host}:{loc.port}{loc.path}"
    if t == "rest":
        return f"REST server {re.sub(r'//[^@/]*@', '//', loc.url)}"
    if t == "s3":
        return f"S3 {loc.endpoint}/{loc.bucket}/{loc.prefix}".rstrip("/")
    if t == "b2":
        return f"Backblaze B2 {loc.bucket}/{loc.prefix}".rstrip("/")
    if t == "smb":
        return f"SMB //{loc.host}/{loc.share}/{loc.path}".rstrip("/")
    if t == "ftp":
        return f"FTP{'S' if loc.tls != 'none' else ''} {loc.user}@{loc.host}:{loc.port}/{loc.path}"
    if t == "webdav":
        return f"WebDAV{' (' + loc.vendor + ')' if loc.vendor != 'other' else ''} {loc.url}/{loc.path}"
    if t == "gdrive":
        return f"Google Drive /{loc.path}"
    return t


class Resolved:
    """What the restic adapter needs: repository string, env vars, `-o` options and secret files."""

    def __init__(self, repository: str, env: dict[str, str] | None = None, options: list[str] | None = None,
                 files: dict[str, str] | None = None, needs_rclone: bool = False):
        self.repository = repository
        self.env = env or {}
        self.options = options or []
        self.files = files or {}  # filename -> content, written 0600 into the adapter's secret dir
        self.needs_rclone = needs_rclone


def resolve(loc: Any, secret: dict[str, Any], secret_dir: Path, *, rclone_binary: str = "rclone",
            obscure=None) -> Resolved:
    """Translate a location + its secrets into restic settings. `obscure` turns a plain password into
    rclone's obscured form (rclone requires it for config passwords)."""
    t = loc.type
    if t == "local":
        return Resolved(loc.path)
    if t == "sftp":
        key = secret.get("private_key", "")
        if "PRIVATE KEY" not in key:
            raise ValueError("SFTP needs an SSH private key (PEM/OpenSSH format)")
        kh = f"[{loc.host}]:{loc.port} {loc.host_key}\n" if loc.port != 22 else f"{loc.host} {loc.host_key}\n"
        key_path, kh_path = secret_dir / "ssh_key", secret_dir / "known_hosts"
        cmd = (f"ssh -i {key_path} -p {loc.port} -o IdentitiesOnly=yes -o BatchMode=yes "
               f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={kh_path} -o ConnectTimeout=20 "
               f"{loc.user}@{loc.host} -s sftp")
        return Resolved(f"sftp:{loc.user}@{loc.host}:{loc.path}", options=[f"sftp.command={cmd}"],
                        files={"ssh_key": key.strip() + "\n", "known_hosts": kh})
    if t == "rest":
        env = {}
        if secret.get("username"):
            env["RESTIC_REST_USERNAME"] = secret["username"]
            env["RESTIC_REST_PASSWORD"] = secret.get("password", "")
        return Resolved(f"rest:{loc.url}", env=env)
    if t == "s3":
        env = {"AWS_ACCESS_KEY_ID": secret.get("access_key", ""), "AWS_SECRET_ACCESS_KEY": secret.get("secret_key", "")}
        if loc.region:
            env["AWS_DEFAULT_REGION"] = loc.region
        ep = loc.endpoint if loc.endpoint.startswith("http") else f"https://{loc.endpoint}"
        return Resolved(f"s3:{ep}/{loc.bucket}" + (f"/{loc.prefix}" if loc.prefix else ""), env=env)
    if t == "b2":
        return Resolved(f"b2:{loc.bucket}:{loc.prefix or '/'}",
                        env={"B2_ACCOUNT_ID": secret.get("account_id", ""), "B2_ACCOUNT_KEY": secret.get("account_key", "")})

    # rclone-backed protocols
    p = f"RCLONE_CONFIG_{RCLONE_REMOTE}_"
    env: dict[str, str] = {}
    if t == "smb":
        env = {p + "TYPE": "smb", p + "HOST": loc.host, p + "PORT": str(loc.port), p + "USER": loc.user,
               p + "DOMAIN": loc.domain}
        if secret.get("password"):
            env[p + "PASS"] = obscure(secret["password"])
        remote_path = f"{loc.share}/{loc.path}".rstrip("/")
    elif t == "ftp":
        env = {p + "TYPE": "ftp", p + "HOST": loc.host, p + "PORT": str(loc.port), p + "USER": loc.user,
               p + "EXPLICIT_TLS": str(loc.tls == "explicit").lower(), p + "TLS": str(loc.tls == "implicit").lower()}
        if secret.get("password"):
            env[p + "PASS"] = obscure(secret["password"])
        remote_path = loc.path
    elif t == "webdav":
        env = {p + "TYPE": "webdav", p + "URL": loc.url, p + "VENDOR": loc.vendor, p + "USER": loc.user}
        if secret.get("password"):
            env[p + "PASS"] = obscure(secret["password"])
        remote_path = loc.path
    elif t == "gdrive":
        token = secret.get("token", "")
        if '"access_token"' not in token and '"refresh_token"' not in token:
            raise ValueError("Google Drive needs the JSON token printed by `rclone authorize \"drive\"`")
        env = {p + "TYPE": "drive", p + "SCOPE": "drive", p + "TOKEN": token}
        if loc.root_folder_id:
            env[p + "ROOT_FOLDER_ID"] = loc.root_folder_id
        remote_path = loc.path
    else:  # pragma: no cover - guarded by the schema
        raise ValueError(f"unknown location type {t}")
    return Resolved(f"rclone:{RCLONE_REMOTE}:{remote_path}", env=env,
                    options=[f"rclone.program={rclone_binary}"], needs_rclone=True)

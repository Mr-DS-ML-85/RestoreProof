"""ResticWriter: the only code allowed to write to a repository (init, backup, forget, prune).

Recovery tests never use this class; their adapter keeps the read-only allowlist.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from restoreproof.adapters.base import AdapterError
from restoreproof.adapters.restic import ALLOWED_SUBCOMMANDS, ResticAdapter, classify_failure

WRITE_SUBCOMMANDS = frozenset({"init", "backup", "forget", "prune"})
TAG_RE = re.compile(r"^[A-Za-z0-9._:=-]{1,100}$")


class ResticWriter(ResticAdapter):
    allowed_subcommands = ALLOWED_SUBCOMMANDS | WRITE_SUBCOMMANDS

    def exists(self) -> tuple[bool, str | None]:
        """(True, None) if the repository opens; (False, code) otherwise."""
        r = self._run("cat", ["config"], timeout=120)
        if r.ok:
            return True, None
        return False, classify_failure(r).code

    def init(self) -> None:
        r = self._run("init", [], timeout=300, no_lock=False, json_out=False)
        if not r.ok:
            raise AdapterError("init_failed", "could not initialise the repository: "
                               + self.sanitizer.text(r.stderr.strip())[-300:])

    def has_tag(self, tag: str) -> bool:
        r = self._run("snapshots", ["--tag", tag], timeout=120)
        return r.ok and bool(json.loads(r.stdout or "[]"))

    def backup(self, paths: list[str], *, excludes: list[str], tags: list[str], host: str, timeout: float,
               poll: Callable[[], None] | None = None) -> dict[str, Any]:
        args: list[str] = ["--host", host]
        for t in tags:
            if not TAG_RE.match(t):
                raise AdapterError("invalid_argument", f"invalid tag {t!r}")
            args += ["--tag", t]
        for e in excludes:
            if e.startswith("-") or "\x00" in e:
                raise AdapterError("invalid_argument", f"invalid exclude pattern {e!r}")
            args += ["--exclude", e]
        for p in paths:
            if not p.startswith("/"):
                raise AdapterError("invalid_argument", f"backup paths must be absolute: {p!r}")
        args += ["--", *paths]
        r = self._run("backup", args, timeout=timeout, poll=poll, no_lock=False)
        summary: dict[str, Any] = {}
        errors: list[str] = []
        # restic prints the summary on stdout but its JSON error records on stderr.
        for line in (r.stdout + "\n" + r.stderr).splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                if line.startswith(("error:", "Fatal:")) or "permission denied" in line:
                    errors.append(line.strip()[:300])
                continue
            if msg.get("message_type") == "summary":
                summary = msg
            elif msg.get("message_type") == "error":
                err = (msg.get("error") or {}).get("message") or ""
                item = msg.get("item") or ""
                errors.append((f"{item}: {err}" if item and item not in err else err or item or str(msg))[:300])
        if r.timed_out or r.aborted:
            raise classify_failure(r)
        if r.returncode == 3 and summary.get("snapshot_id"):
            # Snapshot written, but some files could not be read: that is a backup with holes.
            return {**summary, "partial": True, "errors": self.sanitizer.obj(errors[:50])}
        if r.returncode != 0 or not summary.get("snapshot_id"):
            e = classify_failure(r)
            e.details["log"] = self._log(r)
            e.details["errors"] = errors[:20]
            raise e
        return {**summary, "partial": False, "errors": []}

    def apply_retention(self, tag: str, keep: dict[str, int], *, prune: bool, timeout: float) -> str:
        args = ["--tag", tag, "--group-by", "host,tags"]
        for k in ("last", "daily", "weekly", "monthly", "yearly"):
            if int(keep.get(k) or 0) > 0:
                args += [f"--keep-{k}", str(int(keep[k]))]
        if len(args) == 4:
            return "retention not configured"
        if prune:
            args.append("--prune")
        r = self._run("forget", args, timeout=timeout, no_lock=False, json_out=False)
        if not r.ok:
            return "retention failed: " + self.sanitizer.text(r.stderr.strip())[-300:]
        removed = len(re.findall(r"^remove \d+ snapshots?", r.stdout, re.M))
        return ("forget + prune" if prune else "forget (prune deferred: a recovery test is reading this repository)") + \
            (f": {removed} group(s) trimmed" if removed else ": nothing to remove")

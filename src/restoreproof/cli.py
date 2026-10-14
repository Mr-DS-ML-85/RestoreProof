"""restoreproof <command>

  serve           API + dashboard (uvicorn)
  worker          job worker (with embedded scheduler unless --no-scheduler)
  scheduler       standalone scheduler loop
  migrate         apply database migrations
  create-admin    create an administrator (prompts for password)
  validate FILE   validate a RecoveryTest YAML file
  verify-report   verify a manifest's hash and signature
  reconcile       mark interrupted attempts and clean up orphaned resources now
  gen-key PATH    create a new credential-encryption key file (mode 0600)
  doctor          check this installation (restic, Docker, disk, keys, database, workers)
  templates       list built-in application templates
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import signal
import sys
import threading


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="restoreproof", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    wk = sub.add_parser("worker")
    wk.add_argument("--no-scheduler", action="store_true")
    wk.add_argument("--once", action="store_true", help="run at most one queued job, then exit")
    sub.add_parser("scheduler")
    sub.add_parser("migrate")
    ca = sub.add_parser("create-admin")
    ca.add_argument("email")
    va = sub.add_parser("validate")
    va.add_argument("file")
    vr = sub.add_parser("verify-report")
    vr.add_argument("file")
    vr.add_argument("--fingerprint", help="trusted signing-key fingerprint")
    sub.add_parser("reconcile")
    sub.add_parser("doctor")
    dm = sub.add_parser("demo", help="create demo data and a test (try RestoreProof without your own backup)")
    dm.add_argument("action", nargs="?", default="create", choices=["create", "break", "repair"])
    tp = sub.add_parser("templates")
    tp.add_argument("--markdown", action="store_true", help="print the template catalogue as Markdown")
    gk = sub.add_parser("gen-key")
    gk.add_argument("path")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Migration chatter is noise for interactive commands; services keep INFO for their own logs.
    if args.cmd in ("migrate", "doctor", "templates", "validate", "verify-report", "gen-key", "create-admin"):
        logging.getLogger("alembic").setLevel(logging.WARNING)

    if args.cmd == "validate":
        from restoreproof.definitions import DefinitionError, parse_definition
        try:
            d = parse_definition(open(args.file).read())
        except DefinitionError as exc:
            for e in exc.errors:
                print(f"  {e['loc'] or '<root>'}: {e['msg']}", file=sys.stderr)
            return 1
        print(f"ok: {d.metadata.name} ({len(d.spec.checks)} checks)")
        return 0

    if args.cmd == "gen-key":
        from pathlib import Path

        from restoreproof.security.crypto import load_or_create_key
        path = Path(args.path)
        if path.exists():
            print(f"{path} already exists; refusing to overwrite (it may protect stored credentials)", file=sys.stderr)
            return 1
        load_or_create_key(path)
        print(f"wrote {path}. Back it up separately: without it, stored credentials cannot be decrypted.")
        return 0

    if args.cmd == "verify-report":
        from restoreproof.evidence.manifest import verify
        res = verify(json.load(open(args.file)), args.fingerprint)
        print(json.dumps(res, indent=2))
        return 0 if res["hash_ok"] and res["signature"] in ("valid", "absent") else 2

    from restoreproof.config import ensure_dirs, get_settings
    from restoreproof.db.migrations import upgrade

    ensure_dirs(get_settings())
    if get_settings().auto_migrate or args.cmd == "migrate":
        upgrade()

    if args.cmd == "migrate":
        print("database is at the latest revision")
        return 0

    if args.cmd == "serve":
        import uvicorn

        from restoreproof.main import create_app
        uvicorn.run(create_app(run_migrations=False), host=args.host, port=args.port, proxy_headers=True)
        return 0

    if args.cmd == "create-admin":
        from sqlalchemy import select

        from restoreproof import audit
        from restoreproof.auth.security import hash_password, validate_password_strength
        from restoreproof.db.models import User
        from restoreproof.db.session import session_scope
        pw = getpass.getpass("Password (min 12 chars): ")
        validate_password_strength(pw)
        with session_scope() as s:
            if s.scalar(select(User).where(User.email == args.email.lower())):
                print("user exists", file=sys.stderr)
                return 1
            u = User(email=args.email.lower(), password_hash=hash_password(pw), role="admin")
            s.add(u)
            s.flush()
            audit.record(s, "user.created", target_type="user", target_id=u.id, details={"via": "cli"})
        print("administrator created")
        return 0

    if args.cmd == "demo":
        from restoreproof import demo
        from restoreproof.db.session import session_scope
        with session_scope() as s:
            fn = {"create": demo.create, "break": demo.break_demo, "repair": demo.repair_demo}[args.action]
            try:
                out = fn(s, None)
            except demo.DemoError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
        print(json.dumps(out, indent=2))
        if args.action == "create":
            print("\nOpen the dashboard → Applications → demo-notes → Test recovery now.")
        elif args.action == "break":
            print("\nNow run the demo-notes test again to see a failure and how RestoreProof explains it.")
        return 0

    if args.cmd == "doctor":
        from restoreproof import diagnostics
        items = diagnostics.run()
        icon = {"ok": "✔", "warn": "!", "fail": "✘"}
        for i in items:
            print(f" {icon[i['status']]} {i['name']:<24} {i['detail']}")
            if i["fix"] and i["status"] != "ok":
                print(f"   {'':<24} → {i['fix']}")
        overall = diagnostics.summary(items)
        print(f"\noverall: {overall}")
        return {"ok": 0, "warn": 0, "fail": 1}[overall]

    if args.cmd == "templates":
        from restoreproof.templates import TEMPLATES
        from restoreproof import json_templates
        from restoreproof.api.routes_product import VERIFIED_BUILTIN
        if args.markdown:
            lib = json_templates.library()
            print("# Application templates\n\nGenerated by `restoreproof templates --markdown`. In the dashboard: "
                  "**Applications → Protect an application**. How to write your own: Help → Templates.\n")
            print("| Template | Verified against a real install |\n|---|---|")
            for t in TEMPLATES.values():
                print(f"| {t.name} | {VERIFIED_BUILTIN.get(t.id) or 'not yet'} |")
            for d in lib:
                print(f"| {d.name} | {d.verified or 'not yet'} |")
            print()
            for d in lib:
                print(f"## {d.name}\n\n{d.summary}\n\nJSON template `{d.id}` (export it from the gallery to adapt it)."
                      + (f" Verified with {d.verified}." if d.verified else " Not yet verified against a real install.") + "\n")
                for g in d.backup_guidance:
                    print(f"- Backup tip: {g}")
                if d.backup_guidance:
                    print()
            for t in TEMPLATES.values():
                print(f"## {t.name}\n\n{t.summary}\n\nVerifies: {', '.join(t.layers)}"
                      + (f" · [upstream backup docs]({t.homepage})" if t.homepage else "") + "\n")
                if t.backup_guidance:
                    print("**Back it up so it is restorable**\n")
                    print("\n".join(f"- {g}" for g in t.backup_guidance) + "\n")
                if t.caveats:
                    print("**Notes**\n\n" + "\n".join(f"- {c}" for c in t.caveats) + "\n")
                print("| Field | Default | Meaning |\n|---|---|---|")
                for p in t.params:
                    d = t.id if p.key == "name" else p.default
                    print(f"| {p.label} | `{d}` | {p.help} |")
                print()
            return 0
        for t in TEMPLATES.values():
            print(f"{t.id:<20} {t.name:<34} {'verified' if t.id in VERIFIED_BUILTIN else ''}")
        for d in json_templates.library():
            print(f"{d.id:<20} {d.name:<34} {'verified' if d.verified else 'unverified'}")
        return 0

    if args.cmd == "reconcile":
        from restoreproof.jobs.worker import reconcile
        print(json.dumps(reconcile(), indent=2, default=str))
        return 0

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    if args.cmd == "worker":
        from restoreproof.jobs import worker
        if args.once:
            worker.reconcile()
            print(worker.run_once() or "no runnable job")
            return 0
        worker.run_forever(stop, embedded_scheduler=not args.no_scheduler)
        return 0

    if args.cmd == "scheduler":
        from restoreproof.scheduler.scheduler import tick
        while not stop.is_set():
            try:
                tick()
            except Exception:  # noqa: BLE001
                logging.exception("scheduler tick failed")
            stop.wait(30)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())



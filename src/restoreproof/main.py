from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from restoreproof.api import routes_admin, routes_apps, routes_backups, routes_jobs, routes_product, routes_sources
from restoreproof.config import VERSION, ensure_dirs, get_settings
from restoreproof.db.migrations import upgrade
from restoreproof.db.session import get_engine
from restoreproof.runner.docker import docker_available

STATIC = Path(__file__).parent / "static"


def create_app(run_migrations: bool = True) -> FastAPI:
    settings = get_settings()
    ensure_dirs(settings)
    if run_migrations and settings.auto_migrate:
        upgrade()
    app = FastAPI(title="RestoreProof", version=VERSION,
                  description="Continuously restore backups into isolated environments, verify them, and keep "
                              "evidence. API version v1.")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "http_error", "message": str(exc.detail)}
        return JSONResponse({"error": detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        errs = [{"loc": ".".join(str(p) for p in e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse({"error": {"code": "invalid_request", "message": "request validation failed",
                                       "details": errs}}, status_code=422)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/api/v1/health", tags=["health"])
    def health() -> dict:
        return {"status": "ok", "version": VERSION}

    @app.get("/api/v1/ready", tags=["health"])
    def ready() -> JSONResponse:
        checks: dict[str, dict] = {}
        try:
            with get_engine().connect() as c:
                c.execute(text("SELECT 1"))
            checks["database"] = {"ok": True}
        except Exception as exc:  # noqa: BLE001
            checks["database"] = {"ok": False, "error": type(exc).__name__}
        # Only the worker needs the restore area; the API reports it for visibility.
        checks["temp_root_writable"] = {"ok": settings.temp_root.is_dir() and
                                        os.access(settings.temp_root, os.W_OK), "required": False}
        checks["secret_key"] = {"ok": settings.secret_key_file.exists() and
                                os.access(settings.secret_key_file, os.R_OK)}
        try:
            with get_engine().connect() as c:
                c.execute(text("SELECT 1 FROM alembic_version"))
            checks["schema"] = {"ok": True}
        except Exception:  # noqa: BLE001
            checks["schema"] = {"ok": False, "detail": "migrations have not been applied"}
        ok, ver = docker_available(timeout=5)
        checks["docker"] = {"ok": ok, "detail": ver, "required": False}
        ready_ = all(v["ok"] for k, v in checks.items() if v.get("required", True))
        return JSONResponse({"ready": ready_, "checks": checks}, status_code=200 if ready_ else 503)

    for r in (routes_sources.router, routes_apps.router, routes_jobs.router, routes_admin.router,
              routes_product.router, routes_backups.router):
        app.include_router(r)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return app

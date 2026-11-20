import asyncio
import logging
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from pypi_tea import analytics, db, sentry
from pypi_tea.config import settings
from pypi_tea.lookup import Overloaded, Pending, read
from pypi_tea.routes import pages, seo, stats, tea
from pypi_tea.routes.tea import InvalidRequest
from pypi_tea.tea import LEGACY_TEA_VERSION, TEA_VERSION
from pypi_tea.usage import FLUSH_SECONDS, usage

sentry.init("api")

logger = logging.getLogger("pypi_tea.app")

_STATIC_DIR = Path(__file__).parent / "static"
# The dashboard is static apart from the version; its data loads from /stats.
_INDEX_HTML = pages.render(
    "index.html", nav="dashboard", markdown_url="/index.md", analytics_page={"page_type": "dashboard"}
)


async def _flush_usage_forever() -> None:
    while True:
        await asyncio.sleep(FLUSH_SECONDS)
        try:
            await asyncio.to_thread(usage.flush)
        except Exception:
            logger.exception("usage flush failed")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    db.init_schema(settings.database_path)
    await asyncio.to_thread(analytics.init)
    background: list[asyncio.Task[None]] = [asyncio.create_task(_flush_usage_forever())]
    stop = asyncio.Event()
    if settings.embedded_worker:
        from pypi_tea import worker

        background.append(asyncio.create_task(worker.run(stop)))
    try:
        yield
    finally:
        stop.set()
        for task in background:
            task.cancel()
        for task in background:
            with suppress(asyncio.CancelledError, Exception):
                await task
        with suppress(Exception):
            await asyncio.to_thread(usage.flush)
        await asyncio.to_thread(analytics.shutdown)


app = FastAPI(title="pypi-tea - TEA Server for PyPI SBOMs", lifespan=lifespan)


@app.exception_handler(Overloaded)
async def _overloaded(_request: Request, _exc: Overloaded) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": "Too many lookups in progress, retry later"},
        headers={"Retry-After": "30", "Cache-Control": "no-store"},
    )


@app.exception_handler(InvalidRequest)
async def _invalid_request(_request: Request, exc: InvalidRequest) -> JSONResponse:
    return exc.response()


@app.exception_handler(RequestValidationError)
async def _invalid_parameters(request: Request, exc: RequestValidationError) -> JSONResponse:
    """A TEA 1.0.0 request with a bad parameter gets 400 and a TEA error body; anything else FastAPI's 422."""
    prefix, path = _split_api_path(request.url.path)
    if _API_PREFIXES.get(prefix, False) or path.lstrip("/").split("/", 1)[0] not in _TEA_ENDPOINTS:
        return await request_validation_exception_handler(request, exc)
    detail = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
    return InvalidRequest(detail).response()


@app.exception_handler(Pending)
async def _pending(_request: Request, _exc: Pending) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": "Release is being indexed, retry shortly"},
        headers={"Retry-After": "5", "Cache-Control": "no-store"},
    )


# TEA clients construct versioned base URLs (e.g. /v1.0.0/discovery) after probing
# /.well-known/tea, so the API is mounted under each version prefix. The root serves
# 1.0.0, the default of a client given a base URL without a version. /v0.3.0-beta.2 is
# what earlier releases advertised; it serves 0.4.0 so URLs handed out then keep working.
_API_PREFIXES = {f"/v{TEA_VERSION}": False, f"/v{LEGACY_TEA_VERSION}": True, "/v0.3.0-beta.2": True}


def _version_root(version: str) -> Any:
    async def version_root() -> dict[str, str]:
        """Version prefix root — used by TEA clients to probe endpoint reachability."""
        return {"version": version}

    return version_root


def _split_api_path(path: str) -> tuple[str, str]:
    """`/v1.0.0/discovery` -> (`/v1.0.0`, `/discovery`); a path outside the version prefixes keeps an empty one."""
    prefix = next((p for p in _API_PREFIXES if path == p or path.startswith(p + "/")), "")
    return prefix, path[len(prefix) :]


for _prefix, _legacy in _API_PREFIXES.items():
    _version = LEGACY_TEA_VERSION if _legacy else TEA_VERSION
    app.add_api_route(_prefix, _version_root(_version), methods=["GET", "HEAD"])
    app.include_router(tea.router(_legacy), prefix=_prefix)
    app.include_router(stats.router, prefix=_prefix)
app.include_router(tea.common)
app.include_router(tea.downloads)
app.include_router(tea.router(legacy=False))
app.include_router(stats.router)
app.include_router(pages.router)
app.include_router(seo.router)
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(_INDEX_HTML, headers={"Cache-Control": pages.DASHBOARD_CACHE})


@app.get("/healthz")
async def healthz() -> Any:
    await read(_ping)
    return {"status": "ok"}


def _ping(conn: sqlite3.Connection) -> None:
    conn.execute("SELECT 1").fetchone()


# Edge cache rules for JSON responses (HTML routes set their own). Wheels are
# immutable, so anything derived from one can be cached for a long time.
_CACHE_RULES: tuple[tuple[str, str], ...] = (
    # Fonts and images never change in place; the stylesheet URL carries ?v=<version>.
    ("/static/", "public, max-age=86400, s-maxage=604800, stale-if-error=604800"),
    ("/artifact/", "public, max-age=86400, s-maxage=604800, stale-if-error=604800"),
    ("/component", "public, max-age=86400, s-maxage=604800, stale-if-error=604800"),
    ("/productRelease/", "public, max-age=3600, s-maxage=86400, stale-if-error=604800"),
    ("/product", "public, max-age=3600, s-maxage=3600, stale-if-error=86400"),
    ("/discovery", "public, max-age=3600, s-maxage=3600, stale-if-error=86400"),
    ("/.well-known/tea", "public, max-age=3600, s-maxage=3600"),
    ("/attestation/", "public, max-age=3600, s-maxage=86400"),
    ("/stats", "public, max-age=60, s-maxage=60"),
)
_TEA_ENDPOINTS = frozenset(
    {
        "discovery",
        "products",
        "product",
        "productReleases",
        "productRelease",
        "component",
        "componentRelease",
        "artifact",
    }
)
# Endpoints whose calls are sent to analytics: the TEA API and the attestation lookup.
# The dashboard's own /stats polling and crawler files would only drown them out.
_TRACKED_ENDPOINTS = _TEA_ENDPOINTS | {".well-known", "attestation"}


def _header(scope: Scope, name: bytes) -> str:
    for key, value in scope.get("headers", ()):
        if key == name:
            return bytes(value).decode("latin-1")
    return ""


class EdgeMiddleware:
    """Pure-ASGI middleware: request deadline, cache headers, endpoint usage counts.

    The deadline turns anything stuck (slow disk, an upstream that never answers)
    into a fast 503 instead of a connection the edge holds open until it gives up.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = _split_api_path(scope["path"])[1]
        rule = next((header for prefix, header in _CACHE_RULES if path.startswith(prefix)), None)
        endpoint = path.lstrip("/").split("/", 1)[0]
        tracked = analytics.enabled() and endpoint in _TRACKED_ENDPOINTS
        if tracked:
            client = scope.get("client")
            analytics.begin_request(client[0] if client else "", _header(scope, b"user-agent"), path)
        started_at = time.monotonic()
        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                status = message["status"]
                headers = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() != b"cache-control" or rule is None
                ]
                if rule is not None:
                    value = rule if status < 400 else ("no-store" if status >= 500 else "public, max-age=300")
                    headers.append((b"cache-control", value.encode()))
                message["headers"] = headers
                if status < 400 and endpoint in _TEA_ENDPOINTS:
                    usage.endpoint(endpoint)
                if tracked:
                    analytics.capture(
                        "tea_api_called",
                        {
                            "endpoint": endpoint,
                            "status_code": status,
                            "versioned_url": scope["path"] != path,
                            "duration_ms": round((time.monotonic() - started_at) * 1000, 1),
                        },
                    )
            await send(message)

        try:
            async with asyncio.timeout(settings.request_timeout_seconds):
                await self.app(scope, receive, send_wrapper)
        except TimeoutError:
            if started:
                raise
            if tracked:
                analytics.capture("tea_api_called", {"endpoint": endpoint, "status_code": 503, "timed_out": True})
            response = JSONResponse(
                status_code=503,
                content={"error": "Request timed out"},
                headers={"Retry-After": "10", "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)


app.add_middleware(EdgeMiddleware)

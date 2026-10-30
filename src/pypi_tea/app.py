import asyncio
import logging
import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from importlib.metadata import version
from pathlib import Path
from typing import Any

import sentry_sdk
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from pypi_tea import db
from pypi_tea.config import settings
from pypi_tea.lookup import Overloaded, Pending, read
from pypi_tea.routes import pages, seo, stats, tea
from pypi_tea.usage import FLUSH_SECONDS, usage

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN", ""),
    send_default_pii=False,
    traces_sample_rate=0.01,
    release=version("pypi-tea"),
)

logger = logging.getLogger("pypi_tea.app")

_STATIC_DIR = Path(__file__).parent / "static"
_INDEX_HTML = (_STATIC_DIR / "index.html").read_text().replace("{{VERSION}}", version("pypi-tea"))


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


app = FastAPI(title="pypi-tea - TEA Server for PyPI SBOMs", lifespan=lifespan)


@app.exception_handler(Overloaded)
async def _overloaded(_request: Request, _exc: Overloaded) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": "Too many lookups in progress, retry later"},
        headers={"Retry-After": "30", "Cache-Control": "no-store"},
    )


@app.exception_handler(Pending)
async def _pending(_request: Request, _exc: Pending) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": "Release is being indexed, retry shortly"},
        headers={"Retry-After": "5", "Cache-Control": "no-store"},
    )


# TEA clients construct versioned base URLs (e.g. /v0.3.0-beta.2/discovery)
# after probing /.well-known/tea, so the API is mounted under the version prefix too.
_version_prefix = f"/v{settings.tea_spec_version}"


@app.head(_version_prefix)
@app.get(_version_prefix)
async def version_root() -> dict[str, str]:
    """Version prefix root — used by TEA clients to probe endpoint reachability."""
    return {"version": settings.tea_spec_version}


app.include_router(tea.router)
app.include_router(tea.router, prefix=_version_prefix)
app.include_router(stats.router)
app.include_router(stats.router, prefix=_version_prefix)
app.include_router(pages.router)
app.include_router(seo.router)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(_INDEX_HTML, headers={"Cache-Control": "public, max-age=300, s-maxage=300"})


@app.get("/healthz")
async def healthz() -> Any:
    await read(_ping)
    return {"status": "ok"}


def _ping(conn: sqlite3.Connection) -> None:
    conn.execute("SELECT 1").fetchone()


# Edge cache rules for JSON responses (HTML routes set their own). Wheels are
# immutable, so anything derived from one can be cached for a long time.
_CACHE_RULES: tuple[tuple[str, str], ...] = (
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
        path: str = scope["path"]
        if path.startswith(_version_prefix):
            path = path[len(_version_prefix) :]
        rule = next((header for prefix, header in _CACHE_RULES if path.startswith(prefix)), None)
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
                if status < 400:
                    endpoint = path.lstrip("/").split("/", 1)[0]
                    if endpoint in _TEA_ENDPOINTS:
                        usage.endpoint(endpoint)
            await send(message)

        try:
            async with asyncio.timeout(settings.request_timeout_seconds):
                await self.app(scope, receive, send_wrapper)
        except TimeoutError:
            if started:
                raise
            response = JSONResponse(
                status_code=503,
                content={"error": "Request timed out"},
                headers={"Retry-After": "10", "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)


app.add_middleware(EdgeMiddleware)

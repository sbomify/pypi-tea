import asyncio
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from importlib.metadata import version
from pathlib import Path
from typing import Any

import httpx
import sdnotify
import sentry_sdk
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.routes import (
    artifacts,
    attestation,
    component_releases,
    components,
    discovery,
    pages,
    product_releases,
    products,
    seo,
    stats,
)
from pypi_tea.services.sbom_extractor import init_pool as _init_extraction_pool
from pypi_tea.services.sbom_extractor import shutdown_pool as _shutdown_extraction_pool

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN", ""),
    send_default_pii=True,
    traces_sample_rate=0.1,
    release=version("pypi-tea"),
)

logger = logging.getLogger("pypi_tea.app")

_STATIC_DIR = Path(__file__).parent / "static"


async def _watchdog_loop(notifier: sdnotify.SystemdNotifier, interval: float) -> None:
    """Ping systemd's watchdog; if the event loop hangs, the ping stops and systemd restarts us."""
    while True:
        await asyncio.sleep(interval)
        notifier.notify("WATCHDOG=1")


def _maybe_start_watchdog(notifier: sdnotify.SystemdNotifier) -> asyncio.Task[None] | None:
    """Start the watchdog ping task if sd_notify watchdog env vars are set and valid.

    Returns the Task (so the caller can cancel it on shutdown), or None if the
    watchdog is disabled — missing env vars, unparseable WATCHDOG_USEC, or a
    WATCHDOG_PID that doesn't match the current process (sd_notify will ignore
    pings from any other PID, so there's no point sending them).
    """
    raw_usec = os.environ.get("WATCHDOG_USEC", "0")
    try:
        watchdog_usec = int(raw_usec)
    except ValueError:
        logger.warning("Invalid WATCHDOG_USEC=%r; disabling systemd watchdog", raw_usec)
        return None
    if watchdog_usec <= 0:
        return None

    raw_pid = os.environ.get("WATCHDOG_PID")
    if raw_pid:
        try:
            expected_pid = int(raw_pid)
        except ValueError:
            logger.warning("Invalid WATCHDOG_PID=%r; disabling systemd watchdog", raw_pid)
            return None
        if expected_pid != os.getpid():
            logger.warning(
                "WATCHDOG_PID=%d does not match current pid %d; disabling systemd watchdog",
                expected_pid,
                os.getpid(),
            )
            return None

    interval = (watchdog_usec / 1_000_000) / 2
    task = asyncio.create_task(_watchdog_loop(notifier, interval))
    logger.info("systemd watchdog active, pinging every %.1fs", interval)
    return task


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.http_client = httpx.AsyncClient(
        timeout=30.0,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
        headers={"User-Agent": f"pypi-tea/{version('pypi-tea')} (https://github.com/sbomify/pypi-tea)"},
    )
    app.state.cache = Cache(settings.redis_url)
    await app.state.cache.init()
    _init_extraction_pool()

    # sd_notify wiring: only active when running under systemd with Type=notify.
    # NOTIFY_SOCKET is set by systemd; WATCHDOG_USEC / WATCHDOG_PID are set when
    # WatchdogSec= is configured.  _maybe_start_watchdog handles the pid-match
    # and parse-error edge cases.
    watchdog_task: asyncio.Task[None] | None = None
    if os.environ.get("NOTIFY_SOCKET"):
        notifier = sdnotify.SystemdNotifier()
        notifier.notify("READY=1")
        watchdog_task = _maybe_start_watchdog(notifier)

    try:
        yield
    finally:
        if watchdog_task is not None:
            watchdog_task.cancel()
            with suppress(asyncio.CancelledError):
                await watchdog_task
        _shutdown_extraction_pool()
        await app.state.http_client.aclose()
        await app.state.cache.close()


app = FastAPI(title="pypi-tea - TEA Server for PyPI SBOMs", lifespan=lifespan)

app.include_router(discovery.router)
app.include_router(products.router)
app.include_router(product_releases.router)
app.include_router(components.router)
app.include_router(component_releases.router)
app.include_router(artifacts.router)
app.include_router(stats.router)
app.include_router(attestation.router)
app.include_router(pages.router)
app.include_router(seo.router)

# TEA clients construct versioned base URLs (e.g. /v0.3.0-beta.2/discovery)
# after probing /.well-known/tea, so mount API routes under the version prefix too.
_version_prefix = f"/v{settings.tea_spec_version}"


@app.head(_version_prefix)
@app.get(_version_prefix)
async def version_root() -> dict[str, str]:
    """Version prefix root — used by TEA clients to probe endpoint reachability."""
    return {"version": settings.tea_spec_version}


app.include_router(discovery.router, prefix=_version_prefix)
app.include_router(products.router, prefix=_version_prefix)
app.include_router(product_releases.router, prefix=_version_prefix)
app.include_router(components.router, prefix=_version_prefix)
app.include_router(component_releases.router, prefix=_version_prefix)
app.include_router(artifacts.router, prefix=_version_prefix)
app.include_router(stats.router, prefix=_version_prefix)
app.include_router(attestation.router, prefix=_version_prefix)

# Cache headers for Cloudflare: TEA data is derived from immutable wheels
# and cached in Redis, so responses can be cached at the edge.
_CACHE_RULES: dict[str, str] = {
    "/artifact/": "public, max-age=86400, s-maxage=86400",  # SBOMs from immutable wheels
    "/component": "public, max-age=86400, s-maxage=86400",
    "/product": "public, max-age=3600, s-maxage=3600",  # Shorter — new versions may appear
    "/discovery": "public, max-age=3600, s-maxage=3600",
    "/.well-known/tea": "public, max-age=3600, s-maxage=3600",
    "/stats": "public, max-age=60, s-maxage=60",  # Stats change frequently
    "/package/": "public, max-age=3600, s-maxage=3600",
    "/packages": "public, max-age=300, s-maxage=300",
    "/sitemap": "public, max-age=3600, s-maxage=3600",
}


# TEA endpoint prefixes to track (after stripping version prefix)
_TEA_ENDPOINTS = ("/discovery", "/products", "/product", "/componentRelease", "/component", "/artifact")


@app.middleware("http")
async def add_cache_headers(request: Request, call_next: Any) -> Response:
    response: Response = await call_next(request)
    path = request.url.path
    # Strip version prefix so cache rules match versioned paths too
    if path.startswith(_version_prefix):
        path = path[len(_version_prefix) :]
    for prefix, header in _CACHE_RULES.items():
        if path.startswith(prefix):
            response.headers["Cache-Control"] = header
            break
    # Track TEA endpoint usage
    if response.status_code < 400:
        for ep in _TEA_ENDPOINTS:
            if path.startswith(ep):
                cache = getattr(request.app.state, "cache", None)
                if cache:
                    await cache.track_endpoint(ep.lstrip("/"))
                break
    return response


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html = (_STATIC_DIR / "index.html").read_text()
    return HTMLResponse(
        content=html.replace("{{VERSION}}", version("pypi-tea")),
        headers={"Cache-Control": "public, max-age=300, s-maxage=300"},
    )

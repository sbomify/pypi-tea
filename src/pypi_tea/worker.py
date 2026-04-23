"""arq worker for refreshing PyPI package data.

Jobs:
- resolve_pkg_version(name, version): short-lived unit of work (one PURL resolution)
- check_latest(name, known): query PyPI latest, enqueue resolve if new version
- enqueue_refresh(existing=False, limit=0): fan-out across all tracked packages
- weekly_refresh(): cron wrapper that calls enqueue_refresh(existing=True)

Run with:
    pypi-tea-worker        (console entry point, equivalent to `arq pypi_tea.worker.WorkerSettings`)

Configuration via env vars:
- PYPI_TEA_REDIS_URL: Redis DSN (default redis://localhost:6379)
- PYPI_TEA_WORKER_MAX_JOBS: concurrent jobs per worker (default 5)
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, ClassVar

import httpx
from arq import cron, run_worker
from arq.connections import RedisSettings
from arq.cron import CronJob
from arq.typing import WorkerCoroutine

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.services.mapper import resolve_purl
from pypi_tea.services.sbom_extractor import init_pool, shutdown_pool

# Systemd / journald adds its own timestamps — keep log format simple under it.
if os.environ.get("JOURNAL_STREAM"):
    log_format = "%(levelname)s %(name)s %(message)s"
else:
    log_format = "%(asctime)s %(levelname)s %(name)s %(message)s"

logging.basicConfig(level=logging.INFO, format=log_format)
logger = logging.getLogger("pypi_tea.worker")

REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")
MAX_JOBS = int(os.environ.get("PYPI_TEA_WORKER_MAX_JOBS", "5"))


async def startup(ctx: dict[str, Any]) -> None:
    init_pool()
    ctx["http"] = httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "pypi-tea-worker/1.0 (https://github.com/sbomify/pypi-tea)"},
    )
    cache = Cache(REDIS_URL)
    await cache.init()
    ctx["cache"] = cache
    logger.info("worker started (max_jobs=%d)", MAX_JOBS)


async def shutdown(ctx: dict[str, Any]) -> None:
    http: httpx.AsyncClient | None = ctx.get("http")
    if http is not None:
        await http.aclose()
    cache: Cache | None = ctx.get("cache")
    if cache is not None:
        await cache.close()
    shutdown_pool()
    logger.info("worker shut down")


async def resolve_pkg_version(ctx: dict[str, Any], name: str, version: str) -> str:
    """Resolve a single package@version: fetch metadata, extract SBOMs, cache."""
    purl = f"pkg:pypi/{name}@{version}"
    await resolve_purl(ctx["http"], ctx["cache"], purl)
    return purl


async def check_latest(ctx: dict[str, Any], name: str, known: list[str]) -> str | None:
    """Query PyPI for the latest version; enqueue a resolve job if it's new."""
    http: httpx.AsyncClient = ctx["http"]
    url = f"{settings.pypi_base_url}/pypi/{name}/json"
    try:
        resp = await http.get(url)
    except httpx.HTTPError as e:
        logger.warning("Failed to fetch latest for %s: %s", name, e)
        return None
    if resp.status_code != 200:
        logger.warning("PyPI returned %d for %s", resp.status_code, name)
        return None
    latest: str | None = resp.json().get("info", {}).get("version")
    if not latest or latest in set(known):
        return None
    await ctx["redis"].enqueue_job("resolve_pkg_version", name, latest)
    logger.info("enqueued new version %s@%s", name, latest)
    return latest


async def enqueue_refresh(ctx: dict[str, Any], existing: bool = False, limit: int = 0) -> dict[str, int]:
    """Fan-out job: enqueue one check_latest per package and (if existing) one resolve per known version."""
    cache: Cache = ctx["cache"]
    redis = ctx["redis"]

    entries = await cache.get_tracked_packages()
    packages: dict[str, list[str]] = {}
    for entry in entries:
        name, sep, version = entry.rpartition("@")
        if not sep:
            continue
        packages.setdefault(name, []).append(version)

    names = sorted(packages.keys())
    if limit > 0:
        names = names[:limit]

    check_count = 0
    resolve_count = 0
    for name in names:
        versions = packages[name]
        await redis.enqueue_job("check_latest", name, versions)
        check_count += 1
        if existing:
            for version in versions:
                await redis.enqueue_job("resolve_pkg_version", name, version)
                resolve_count += 1

    logger.info(
        "enqueued %d check_latest and %d resolve_pkg_version jobs (existing=%s)",
        check_count,
        resolve_count,
        existing,
    )
    return {"checks": check_count, "resolves": resolve_count, "packages": len(names)}


async def weekly_refresh(ctx: dict[str, Any]) -> dict[str, int]:
    """Cron entry point: refresh all existing packages and detect new versions."""
    return await enqueue_refresh(ctx, existing=True)


class WorkerSettings:
    functions: ClassVar[list[WorkerCoroutine]] = [
        resolve_pkg_version,
        check_latest,
        enqueue_refresh,
        weekly_refresh,
    ]
    cron_jobs: ClassVar[list[CronJob]] = [cron(weekly_refresh, weekday="sun", hour=3, minute=0, run_at_startup=False)]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(REDIS_URL)
    max_jobs = MAX_JOBS
    job_timeout = 300  # 5 min per job — enough for a wheel SBOM extraction
    max_tries = 3
    keep_result = 3600


def cli() -> None:
    try:
        run_worker(WorkerSettings)  # type: ignore[arg-type]
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    cli()

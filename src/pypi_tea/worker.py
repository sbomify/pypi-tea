"""Ingest worker: drains the `jobs` table and keeps known projects fresh.

All upstream I/O (PyPI JSON, wheel range requests, provenance) happens here and
never in the API process. Concurrency is fixed (`PYPI_TEA_WORKER_CONCURRENCY`),
so a burst of lookups lengthens the queue rather than multiplying outbound
connections, threads and memory.

Run with `pypi-tea-worker`.
"""

import asyncio
import contextlib
import logging
import os
import random
import signal
import sqlite3
import sys
import time
from importlib.metadata import version as pkg_version

import httpx

from pypi_tea import db, jobs, store
from pypi_tea.config import settings
from pypi_tea.ingest import ingest_release, latest_version

if os.environ.get("JOURNAL_STREAM"):
    _LOG_FORMAT = "%(levelname)s %(name)s %(message)s"
else:
    _LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

logger = logging.getLogger("pypi_tea.worker")

IDLE_POLL_SECONDS = 0.25
REFRESH_INTERVAL = 7 * 86400
SCHEDULER_TICK = 60
_LAST_REFRESH_KEY = "last_refresh"
_LISTING_BUILT_KEY = "listing_built_from"


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        limits=httpx.Limits(max_connections=64, max_keepalive_connections=32),
        headers={"User-Agent": f"pypi-tea/{pkg_version('pypi-tea')} (https://github.com/sbomify/pypi-tea)"},
    )


def _conn() -> sqlite3.Connection:
    return db.writer(settings.database_path)


def _claim() -> jobs.Job | None:
    return jobs.claim(_conn())


def _complete(job: jobs.Job) -> None:
    jobs.complete(_conn(), job)


def _retry(job: jobs.Job, error: str) -> bool:
    return jobs.retry_later(_conn(), job, error)


def _enqueue(name: str, version: str, priority: int) -> None:
    jobs.enqueue(_conn(), name, version, priority)


def _known(name: str, version: str) -> bool:
    return store.release_exists(_conn(), name, version)


async def run_job(client: httpx.AsyncClient, job: jobs.Job) -> None:
    if job.version == "":
        latest = await latest_version(client, job.name)
        if latest and not await asyncio.to_thread(_known, job.name, latest):
            await asyncio.to_thread(_enqueue, job.name, latest, job.priority)
        return
    await ingest_release(client, job.name, job.version)


async def _job_loop(client: httpx.AsyncClient, stop: asyncio.Event) -> None:
    while not stop.is_set():
        job = await asyncio.to_thread(_claim)
        if job is None:
            # Jitter so idle loops don't poll in lockstep.
            await asyncio.sleep(IDLE_POLL_SECONDS * (0.5 + random.random()))
            continue
        try:
            await run_job(client, job)
        except Exception as e:
            kept = await asyncio.to_thread(_retry, job, f"{type(e).__name__}: {e}")
            log = logger.warning if kept else logger.error
            log(
                "job %s@%s failed (attempt %d%s): %s",
                job.name,
                job.version,
                job.attempts,
                "" if kept else ", giving up",
                e,
            )
        else:
            await asyncio.to_thread(_complete, job)


def enqueue_refresh(existing: bool = True, limit: int = 0) -> tuple[int, int]:
    """Queue a latest-version check for every project, and optionally a re-resolve of every release."""
    conn = _conn()
    names = store.all_product_names(conn)
    if limit:
        names = names[:limit]
    jobs.enqueue_many(conn, [(n, "") for n in names], jobs.PRIORITY_REFRESH)
    releases: list[tuple[str, str]] = []
    if existing:
        wanted = set(names)
        releases = [k for k in store.all_release_keys(conn) if k[0] in wanted]
        jobs.enqueue_many(conn, releases, jobs.PRIORITY_REFRESH)
    return len(names), len(releases)


def _maybe_schedule_refresh() -> None:
    conn = _conn()
    last = store.get_meta(conn, _LAST_REFRESH_KEY)
    now = int(time.time())
    if last is None:
        # First start: don't refresh straight away, just start the clock.
        store.set_meta(conn, _LAST_REFRESH_KEY, str(now))
        return
    if now - int(last) < REFRESH_INTERVAL:
        return
    store.set_meta(conn, _LAST_REFRESH_KEY, str(now))
    projects, releases = enqueue_refresh(existing=True)
    logger.info("scheduled refresh: %d projects, %d releases", projects, releases)


def _maybe_rebuild_listing() -> None:
    """Rebuild the browse listing when anything was resolved since the last build."""
    conn = _conn()
    latest = store.last_resolved_at(conn)
    built = store.get_meta(conn, _LISTING_BUILT_KEY)
    if built is not None and int(built) >= latest:
        return
    n = store.rebuild_listing(conn)
    store.set_meta(conn, _LISTING_BUILT_KEY, str(latest))
    logger.info("rebuilt package listing (%d releases with SBOMs)", n)


async def _scheduler(stop: asyncio.Event) -> None:
    while not stop.is_set():
        for task in (_maybe_rebuild_listing, _maybe_schedule_refresh):
            try:
                await asyncio.to_thread(task)
            except Exception:
                logger.exception("scheduler task %s failed", task.__name__)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=SCHEDULER_TICK)


async def run(stop: asyncio.Event, concurrency: int | None = None, schedule: bool = True) -> None:
    db.init_schema(settings.database_path)
    n = concurrency or settings.worker_concurrency
    async with make_client() as client:
        tasks = [asyncio.create_task(_job_loop(client, stop)) for _ in range(n)]
        if schedule:
            tasks.append(asyncio.create_task(_scheduler(stop)))
        logger.info("worker started (concurrency=%d, db=%s)", n, settings.database_path)
        try:
            await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def cli() -> None:
    logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)

    async def main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await run(stop)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    cli()

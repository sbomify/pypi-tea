"""Ingest worker: drains the `jobs` table and keeps known projects fresh.

All upstream I/O (PyPI JSON, wheel range requests, provenance) happens here and
never in the API process. Concurrency is fixed (`PYPI_TEA_WORKER_CONCURRENCY`),
so a burst of lookups lengthens the queue rather than multiplying outbound
connections, threads and memory.

Run with `pypi-tea-worker`.
"""

import asyncio
import logging
import os
import random
import signal
import sqlite3
import sys
import time
from collections.abc import Callable
from importlib.metadata import version as pkg_version

import httpx

from pypi_tea import analytics, db, jobs, sentry, store
from pypi_tea.config import settings
from pypi_tea.ingest import ingest_release, latest_version, shutdown_validation_pool

if os.environ.get("JOURNAL_STREAM"):
    _LOG_FORMAT = "%(levelname)s %(name)s %(message)s"
else:
    _LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

logger = logging.getLogger("pypi_tea.worker")

IDLE_POLL_SECONDS = 0.25
# A job that only failed because the database was busy goes back on the queue this soon.
BUSY_RETRY_SECONDS = 5
REFRESH_INTERVAL = 7 * 86400
SCHEDULER_TICK = 2.0
REFRESH_CHECK_INTERVAL = 600.0
# Rebuild the listing promptly after a change, but leave the writer free at least
# LISTING_DUTY_FACTOR times as long as the last rebuild took.
LISTING_DUTY_FACTOR = 10
_LAST_REFRESH_KEY = "last_refresh"
_LISTING_BUILT_KEY = "listing_built_from"


# Set when a job finishes so the scheduler checks the catalog straight away.
# Created per run() so it's bound to the running event loop.
_wake: asyncio.Event | None = None


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        limits=httpx.Limits(max_connections=64, max_keepalive_connections=32),
        headers={"User-Agent": f"pypi-tea/{pkg_version('pypi-tea')} (https://github.com/sbomify/pypi-tea)"},
    )


def _conn() -> sqlite3.Connection:
    return db.writer(settings.database_path)


def _claim() -> jobs.Job | None:
    with db.write_lock:
        return jobs.claim(_conn())


def _complete(job: jobs.Job) -> None:
    with db.write_lock:
        jobs.complete(_conn(), job)


def _retry(job: jobs.Job, error: str) -> bool:
    with db.write_lock:
        return jobs.retry_later(_conn(), job, error)


def _defer(job: jobs.Job) -> None:
    with db.write_lock:
        jobs.defer(_conn(), job, BUSY_RETRY_SECONDS)


def _enqueue(name: str, version: str, priority: int) -> None:
    with db.write_lock:
        jobs.enqueue(_conn(), name, version, priority)


def _known(name: str, version: str) -> bool:
    return store.release_exists(_conn(), name, version)


async def run_job(client: httpx.AsyncClient, job: jobs.Job) -> None:
    if job.version == "":
        latest = await latest_version(client, job.name)
        if latest and not await asyncio.to_thread(_known, job.name, latest):
            await asyncio.to_thread(_enqueue, job.name, latest, job.priority)
        return
    started = time.monotonic()
    release = await ingest_release(client, job.name, job.version, final_attempt=job.attempts >= jobs.MAX_ATTEMPTS)
    if _wake is not None:
        _wake.set()
    if job.priority == jobs.PRIORITY_INTERACTIVE:
        # Only releases someone asked for: backfill and refresh are bulk work, not user behaviour.
        sboms = [s for w in release.wheels for s in w.sboms] if release else []
        analytics.capture(
            "release_indexed",
            {
                "package": job.name,
                "version": job.version,
                "trigger": "lookup",
                "on_pypi": release is not None,
                "wheel_count": len(release.wheels) if release else 0,
                "has_sbom": bool(sboms),
                "sbom_count": len(sboms),
                "sbom_formats": sorted({s.family for s in sboms}),
                "attempts": job.attempts,
                "duration_ms": round((time.monotonic() - started) * 1000),
            },
            distinct_id="pypi-tea-worker",
        )


async def _job_loop(client: httpx.AsyncClient, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            job = await asyncio.to_thread(_claim)
        except sqlite3.OperationalError as e:
            # A busy database must not end the loop: gather() would take the whole worker down with it.
            logger.warning("claiming a job failed: %s", e)
            await asyncio.sleep(IDLE_POLL_SECONDS * (0.5 + random.random()))
            continue
        if job is None:
            # Jitter so idle loops don't poll in lockstep.
            await asyncio.sleep(IDLE_POLL_SECONDS * (0.5 + random.random()))
            continue
        try:
            await run_job(client, job)
        except Exception as e:
            await _settle_failed(job, e)
        else:
            await _settle(_complete, job)


async def _settle_failed(job: jobs.Job, e: Exception) -> None:
    if db.is_busy(e):
        # Contention, not a problem with the release: retry soon without spending an attempt.
        logger.info("job %s@%s deferred: %s", job.name, job.version, e)
        await _settle(_defer, job)
        return
    try:
        kept = await asyncio.to_thread(_retry, job, f"{type(e).__name__}: {e}")
    except sqlite3.OperationalError as release_error:
        logger.warning("job %s@%s: releasing it failed, its lease will lapse: %s", job.name, job.version, release_error)
        kept = True
    log = logger.warning if kept else logger.error
    # Several httpx errors (ConnectTimeout, ReadError) stringify to "".
    log(
        "job %s@%s failed (attempt %d%s): %s: %s",
        job.name,
        job.version,
        job.attempts,
        "" if kept else ", giving up",
        type(e).__name__,
        e,
    )


async def _settle(fn: Callable[[jobs.Job], object], job: jobs.Job) -> None:
    """Record a job's outcome. If even that fails, the lease lapses and the job runs again, which is safe."""
    try:
        await asyncio.to_thread(fn, job)
    except sqlite3.OperationalError as e:
        logger.warning("job %s@%s: recording the outcome failed, its lease will lapse: %s", job.name, job.version, e)


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
    """Rebuild the SBOM listings when a release's SBOM formats changed since the last build.

    A re-resolve that changes nothing (the weekly refresh, mostly) doesn't count.
    """
    conn = _conn()
    latest = store.catalog_version(conn)
    built = store.get_meta(conn, _LISTING_BUILT_KEY)
    if built is not None and int(built) >= latest:
        return
    with db.write_lock:
        n = store.rebuild_listing(conn)
        store.set_meta(conn, _LISTING_BUILT_KEY, str(latest))
    logger.info("rebuilt package listing (%d releases with SBOMs)", n)


async def _wait_for_any(*events: asyncio.Event, timeout: float) -> None:
    waiters = [asyncio.ensure_future(e.wait()) for e in events]
    try:
        await asyncio.wait(waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for w in waiters:
            w.cancel()


async def _scheduler(stop: asyncio.Event, wake: asyncio.Event) -> None:
    next_listing = 0.0
    next_refresh_check = 0.0
    while not stop.is_set():
        wake.clear()
        now = time.monotonic()
        if now >= next_listing:
            try:
                await asyncio.to_thread(_maybe_rebuild_listing)
            except Exception:
                logger.exception("listing rebuild failed")
            took = time.monotonic() - now
            next_listing = time.monotonic() + took * LISTING_DUTY_FACTOR
        if now >= next_refresh_check:
            try:
                await asyncio.to_thread(_maybe_schedule_refresh)
            except Exception:
                logger.exception("refresh scheduling failed")
            next_refresh_check = now + REFRESH_CHECK_INTERVAL
        # Hold off until the next listing slot, then sleep until a job finishes or the tick ends.
        hold = next_listing - time.monotonic()
        if hold > 0:
            await _wait_for_any(stop, timeout=min(hold, SCHEDULER_TICK))
        await _wait_for_any(stop, wake, timeout=SCHEDULER_TICK)


async def run(stop: asyncio.Event, concurrency: int | None = None, schedule: bool = True) -> None:
    db.init_schema(settings.database_path)
    await asyncio.to_thread(analytics.init)
    n = concurrency or settings.worker_concurrency
    async with make_client() as client:
        tasks = [asyncio.create_task(_job_loop(client, stop)) for _ in range(n)]
        if schedule:
            global _wake
            _wake = asyncio.Event()
            tasks.append(asyncio.create_task(_scheduler(stop, _wake)))
        logger.info("worker started (concurrency=%d, db=%s)", n, settings.database_path)
        try:
            await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            shutdown_validation_pool()
            await asyncio.to_thread(analytics.shutdown)


def cli() -> None:
    logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
    # httpx logs every request at INFO: several per wheel, thousands a minute during a backfill.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    sentry.init("worker")

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

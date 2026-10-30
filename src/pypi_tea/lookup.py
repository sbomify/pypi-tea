"""Read-path access to the store, plus on-demand resolution with backpressure.

The API never talks to PyPI. A TEA lookup for a release we haven't seen queues
an interactive job for the worker and waits a bounded time for it. Waiting is
capped per process and the shared queue depth is capped globally; past either
limit the request is shed with 503 + Retry-After instead of piling up.
"""

import asyncio
import sqlite3
import time
from collections.abc import Callable

from anyio import to_thread

from pypi_tea import db, jobs, store
from pypi_tea.config import settings
from pypi_tea.models import ReleaseRecord

POLL_SECONDS = 0.2
MAX_WAITERS_PER_PROCESS = 64
_DEPTH_TTL = 1.0


class Overloaded(Exception):
    """Too much on-demand work is already queued; the client should retry later."""


class Pending(Exception):
    """The release is queued but not resolved yet; the client should retry shortly."""


def _read_conn() -> sqlite3.Connection:
    return db.reader(settings.database_path)


async def read[T](fn: Callable[..., T], *args: object) -> T:
    """Run a store query against this thread's read-only connection, off the event loop."""

    def call() -> T:
        return fn(_read_conn(), *args)

    return await to_thread.run_sync(call)


async def write[T](fn: Callable[..., T], *args: object) -> T:
    def call() -> T:
        return fn(db.writer(settings.database_path), *args)

    return await to_thread.run_sync(call)


class _Gate:
    def __init__(self) -> None:
        self.waiters = 0
        self._depth = 0
        self._depth_at = 0.0

    async def queue_depth(self) -> int:
        now = time.monotonic()
        if now - self._depth_at > _DEPTH_TTL:
            self._depth = await read(jobs.pending_interactive)
            self._depth_at = now
        return self._depth


_gate = _Gate()


async def ensure_release(name: str, version: str) -> ReleaseRecord | None:
    """Return the stored release, resolving it on demand. None means PyPI doesn't have it.

    Raises Overloaded or Pending when the answer isn't available within budget.
    """
    release = await read(store.get_release, name, version)
    if release is not None:
        return release
    if await read(store.is_missing, name, version):
        return None
    if _gate.waiters >= MAX_WAITERS_PER_PROCESS or await _gate.queue_depth() >= settings.max_pending_lookups:
        raise Overloaded
    await write(jobs.enqueue, name, version, jobs.PRIORITY_INTERACTIVE)

    _gate.waiters += 1
    try:
        deadline = time.monotonic() + settings.resolve_wait_seconds
        while time.monotonic() < deadline:
            await asyncio.sleep(POLL_SECONDS)
            if await read(store.release_exists, name, version):
                return await read(store.get_release, name, version)
            if await read(store.is_missing, name, version):
                return None
        raise Pending
    finally:
        _gate.waiters -= 1


_memo: dict[str, tuple[float, object]] = {}


async def memoized[T](key: str, ttl: float, fn: Callable[..., T], *args: object) -> T:
    """Per-process TTL cache for aggregate queries (counts, stats) that don't need to be exact to the second."""
    now = time.monotonic()
    hit = _memo.get(key)
    if hit is not None and now - hit[0] < ttl:
        return hit[1]  # type: ignore[return-value]
    value = await read(fn, *args)
    _memo[key] = (now, value)
    return value

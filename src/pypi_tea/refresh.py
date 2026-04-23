"""Enqueue a refresh fan-out job onto the arq queue.

The worker (`pypi-tea-worker`) pops and processes the individual jobs. This CLI
is a thin trigger — it enqueues a single `enqueue_refresh` job and exits. Use
it for manual refreshes; the worker's cron schedule handles the weekly run.

Usage:
    pypi-tea-refresh                 # enqueue new-version detection only
    pypi-tea-refresh --existing      # also re-resolve every known version
    pypi-tea-refresh --limit 100     # cap number of packages (useful for testing)

Exit codes:
    0 - Job enqueued
    2 - Unexpected error
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from arq import create_pool
from arq.connections import RedisSettings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("pypi_tea.refresh")

REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Enqueue a pypi-tea refresh job")
    parser.add_argument("--existing", action="store_true", help="Also re-resolve existing versions")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of packages to process")
    args = parser.parse_args()

    pool = await create_pool(RedisSettings.from_dsn(REDIS_URL))
    try:
        job = await pool.enqueue_job("enqueue_refresh", existing=args.existing, limit=args.limit)
    finally:
        await pool.aclose()

    if job is None:
        logger.error("Failed to enqueue refresh job (duplicate job_id?)")
        sys.exit(2)
    logger.info("Enqueued refresh job %s (existing=%s, limit=%d)", job.job_id, args.existing, args.limit)


def cli() -> None:
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        logger.critical("Unexpected error: %s", e)
        sys.exit(2)


if __name__ == "__main__":
    cli()

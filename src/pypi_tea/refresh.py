"""Enqueue a refresh fan-out job onto the arq queue.

The worker (`pypi-tea-worker`) pops and processes the individual jobs. This CLI
is a thin trigger — it enqueues a single `enqueue_refresh` job and exits. Use
it for manual refreshes; the worker's cron schedule handles the weekly run.

Usage:
    pypi-tea-refresh                 # enqueue new-version detection only
    pypi-tea-refresh --existing      # also re-resolve every known version
    pypi-tea-refresh --limit 100     # cap number of packages (useful for testing)
    pypi-tea-refresh --dry-run       # log what would be enqueued without enqueueing

Exit codes:
    0   - Job enqueued
    2   - Unexpected error (e.g., Redis unavailable, unexpected arq state)
    130 - Interrupted by SIGINT / Ctrl-C
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
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what the fan-out would enqueue without actually enqueueing",
    )
    args = parser.parse_args()

    pool = await create_pool(RedisSettings.from_dsn(REDIS_URL))
    try:
        job = await pool.enqueue_job(
            "enqueue_refresh",
            existing=args.existing,
            limit=args.limit,
            dry_run=args.dry_run,
        )
    finally:
        await pool.aclose()

    # arq only returns None from enqueue_job when a deterministic _job_id
    # collides with an in-queue / recently-completed job.  We don't pass one,
    # so a None here indicates an unexpected arq/Redis state.
    if job is None:
        logger.error("Failed to enqueue refresh job (unexpected arq/Redis state)")
        sys.exit(2)
    logger.info(
        "Enqueued refresh job %s (existing=%s, limit=%d, dry_run=%s)",
        job.job_id,
        args.existing,
        args.limit,
        args.dry_run,
    )


def cli() -> None:
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(2)


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
"""Refresh all tracked packages: detect new versions and update cached data.

This script:
1. Reads all known package@version pairs from Redis
2. Queries PyPI for the latest version of each package
3. If a newer version exists, resolves it via the normal pipeline (metadata, SBOMs, attestations)
4. Optionally re-resolves existing versions to refresh expired caches

Run periodically (e.g. weekly systemd timer):
    uv run python scripts/refresh_packages.py --existing

Options:
    --existing       Also re-resolve existing versions (refresh expired caches)
    --dry-run        Show what would be refreshed without making changes
    --limit N        Only process the first N packages (useful for testing)
    --delay SECONDS  Delay between packages to avoid hammering PyPI (default: 1.0)
    --concurrency N  Number of packages to process in parallel (default: 5)

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).

Exit codes:
    0 - Success (or dry-run)
    1 - Too many errors (>50% of packages failed)
    2 - Unexpected crash
"""

import argparse
import asyncio
import logging
import os
import sys
import time

# Allow importing from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx
import redis.asyncio as redis

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.services.mapper import resolve_purl
from pypi_tea.services.sbom_extractor import init_pool, shutdown_pool

# Use simpler log format under systemd (journald adds timestamps)
if os.environ.get("JOURNAL_STREAM"):
    log_format = "%(levelname)s %(message)s"
else:
    log_format = "%(asctime)s %(levelname)s %(message)s"

logging.basicConfig(level=logging.INFO, format=log_format)
logger = logging.getLogger("refresh")

REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")


async def get_latest_version(client: httpx.AsyncClient, package: str) -> str | None:
    """Fetch the latest version of a package from PyPI."""
    url = f"{settings.pypi_base_url}/pypi/{package}/json"
    try:
        resp = await client.get(url)
        if resp.status_code != 200:
            logger.warning("PyPI returned %d for %s", resp.status_code, package)
            return None
        data = resp.json()
        return data.get("info", {}).get("version")
    except httpx.HTTPError as e:
        logger.warning("Failed to fetch latest version for %s: %s", package, e)
        return None


async def process_package(
    name: str,
    known_versions: set[str],
    client: httpx.AsyncClient,
    cache: Cache,
    semaphore: asyncio.Semaphore,
    delay: float,
    existing: bool,
    dry_run: bool,
    index: int,
    total: int,
) -> tuple[int, int, int]:
    """Process a single package. Returns (new_versions, refreshed, errors)."""
    new_versions = 0
    refreshed = 0
    errors = 0

    async with semaphore:
        known_str = ", ".join(sorted(known_versions))
        logger.info("[%d/%d] Checking %s (known: %s)", index, total, name, known_str)

        latest = await get_latest_version(client, name)
        if latest is None:
            errors += 1
            return new_versions, refreshed, errors

        # Check for new version
        if latest not in known_versions:
            logger.info("  New version found: %s %s", name, latest)
            if not dry_run:
                try:
                    purl = f"pkg:pypi/{name}@{latest}"
                    await resolve_purl(client, cache, purl)
                    new_versions += 1
                    logger.info("  Resolved %s@%s", name, latest)
                except Exception as e:
                    logger.error("  Failed to resolve %s@%s: %s", name, latest, e)
                    errors += 1
            else:
                new_versions += 1

        # Optionally re-resolve existing versions
        if existing:
            for version in sorted(known_versions):
                if dry_run:
                    logger.info("  Would refresh %s@%s", name, version)
                    refreshed += 1
                    continue
                try:
                    purl = f"pkg:pypi/{name}@{version}"
                    await resolve_purl(client, cache, purl)
                    refreshed += 1
                    logger.info("  Refreshed %s@%s", name, version)
                except Exception as e:
                    logger.error("  Failed to refresh %s@%s: %s", name, version, e)
                    errors += 1

        if delay > 0:
            await asyncio.sleep(delay)

    return new_versions, refreshed, errors


async def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh tracked packages")
    parser.add_argument("--existing", action="store_true", help="Also re-resolve existing versions")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be refreshed")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of packages to process")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay in seconds between packages (default: 1.0)")
    parser.add_argument("--concurrency", type=int, default=5, help="Max concurrent package processing (default: 5)")
    args = parser.parse_args()

    start = time.monotonic()

    r = redis.from_url(REDIS_URL, decode_responses=True)

    # Get all tracked package@version pairs
    all_entries: set[str] = await r.smembers("unique:packages")  # type: ignore[assignment]
    await r.aclose()

    # Extract unique package names and their known versions
    packages: dict[str, set[str]] = {}
    for entry in all_entries:
        parts = entry.rsplit("@", 1)
        if len(parts) != 2:
            continue
        name, version = parts
        packages.setdefault(name, set()).add(version)

    package_names = sorted(packages.keys())
    if args.limit > 0:
        package_names = package_names[: args.limit]

    logger.info("Found %d unique packages (%d total versions)", len(package_names), len(all_entries))

    # Set up HTTP client, cache, and extraction pool
    init_pool()
    cache = Cache(REDIS_URL)
    await cache.init()

    semaphore = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "pypi-tea-refresh/1.0 (https://github.com/sbomify/pypi-tea)"},
    ) as client:
        tasks = [
            process_package(
                name=name,
                known_versions=packages[name],
                client=client,
                cache=cache,
                semaphore=semaphore,
                delay=args.delay,
                existing=args.existing,
                dry_run=args.dry_run,
                index=i,
                total=len(package_names),
            )
            for i, name in enumerate(package_names, 1)
        ]

        results = await asyncio.gather(*tasks)

    await cache.close()
    shutdown_pool()

    total_new = sum(r[0] for r in results)
    total_refreshed = sum(r[1] for r in results)
    total_errors = sum(r[2] for r in results)
    elapsed = time.monotonic() - start

    logger.info(
        "Completed in %.1fs. Packages: %d, New versions: %d, Refreshed: %d, Errors: %d",
        elapsed,
        len(package_names),
        total_new,
        total_refreshed,
        total_errors,
    )

    # Exit with failure if too many errors
    if len(package_names) > 0 and total_errors / len(package_names) > 0.5:
        logger.error("Too many errors (%d/%d), exiting with failure", total_errors, len(package_names))
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        logger.critical("Unexpected error: %s", e)
        sys.exit(2)

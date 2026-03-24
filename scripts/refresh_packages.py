#!/usr/bin/env python3
"""Refresh all tracked packages: detect new versions and update cached data.

This script:
1. Reads all known package@version pairs from Redis
2. Queries PyPI for the latest version of each package
3. If a newer version exists, resolves it via the normal pipeline (metadata, SBOMs, attestations)
4. Optionally re-resolves existing versions to refresh expired caches

Run periodically (e.g. daily cron):
    uv run python scripts/refresh_packages.py

Options:
    --existing   Also re-resolve existing versions (refresh expired caches)
    --dry-run    Show what would be refreshed without making changes
    --limit N    Only process the first N packages (useful for testing)

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).
"""

import argparse
import asyncio
import logging
import os
import sys

# Allow importing from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx
import redis.asyncio as redis

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.services.mapper import resolve_purl

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
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


async def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh tracked packages")
    parser.add_argument("--existing", action="store_true", help="Also re-resolve existing versions")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be refreshed")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of packages to process")
    args = parser.parse_args()

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

    # Set up HTTP client and cache
    cache = Cache(REDIS_URL)
    await cache.init()

    async with httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "pypi-tea-refresh/1.0 (https://github.com/sbomify/pypi-tea)"},
    ) as client:
        new_versions = 0
        refreshed = 0
        errors = 0

        for i, name in enumerate(package_names, 1):
            known_versions = packages[name]
            known_str = ", ".join(sorted(known_versions))
            logger.info("[%d/%d] Checking %s (known: %s)", i, len(package_names), name, known_str)

            latest = await get_latest_version(client, name)
            if latest is None:
                errors += 1
                continue

            # Check for new version
            if latest not in known_versions:
                logger.info("  New version found: %s %s", name, latest)
                if not args.dry_run:
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
            if args.existing:
                for version in sorted(known_versions):
                    if args.dry_run:
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

    await cache.close()

    logger.info("Done! New versions: %d, Refreshed: %d, Errors: %d", new_versions, refreshed, errors)


if __name__ == "__main__":
    asyncio.run(main())

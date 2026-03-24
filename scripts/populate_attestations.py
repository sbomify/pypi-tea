#!/usr/bin/env python3
"""Populate PEP 740 attestation data for all tracked wheels.

This script:
1. Reads all known wheel URLs from Redis (both with and without SBOMs)
2. Checks which wheels are missing attestation data
3. Fetches and verifies PEP 740 provenance from PyPI's integrity API
4. Caches results and updates stats

Run after initial data population or to backfill attestation data:
    uv run python scripts/populate_attestations.py

Options:
    --dry-run    Show what would be checked without making requests
    --limit N    Only process first N wheels (useful for testing)
    --force      Re-check even if attestation is already cached

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
import redis.asyncio as aioredis

from pypi_tea.cache import Cache
from pypi_tea.services.attestation import check_wheel_attestation
from pypi_tea.services.pypi import WheelInfo

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("populate_attestations")

REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")


def parse_wheel_url(wheel_url: str) -> tuple[str, str, str] | None:
    """Extract (package, version, filename) from a wheel URL.

    Wheel filenames follow: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
    """
    filename = wheel_url.rsplit("/", 1)[-1] if "/" in wheel_url else wheel_url
    if not filename.endswith(".whl"):
        return None
    parts = filename.split("-")
    if len(parts) < 3:
        return None
    # Normalize package name: underscores → hyphens for PyPI API
    package = parts[0].replace("_", "-").lower()
    version = parts[1]
    return package, version, filename


async def main() -> None:
    parser = argparse.ArgumentParser(description="Populate attestation data for tracked wheels")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be checked")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of wheels to process")
    parser.add_argument("--force", action="store_true", help="Re-check even if cached")
    args = parser.parse_args()

    r = aioredis.from_url(REDIS_URL, decode_responses=True)

    # Collect all known wheel URLs
    wheels_with: set[str] = await r.smembers("unique:wheels_with_sbom")  # type: ignore[assignment]
    wheels_without: set[str] = await r.smembers("unique:wheels_without_sbom")  # type: ignore[assignment]
    all_wheels = sorted(wheels_with | wheels_without)
    await r.aclose()

    logger.info(
        "Found %d total wheels (%d with SBOM, %d without)", len(all_wheels), len(wheels_with), len(wheels_without)
    )

    if args.limit > 0:
        all_wheels = all_wheels[: args.limit]
        logger.info("Limited to %d wheels", len(all_wheels))

    cache = Cache(REDIS_URL)
    await cache.init()

    # Filter out already-cached wheels (unless --force)
    to_check: list[str] = []
    skipped = 0
    for url in all_wheels:
        if not args.force:
            cached = await cache.get_attestation(url)
            if cached is not None:
                skipped += 1
                continue
        to_check.append(url)

    logger.info("Skipped %d already-cached wheels, %d to check", skipped, len(to_check))

    if args.dry_run:
        for url in to_check:
            parsed = parse_wheel_url(url)
            if parsed:
                pkg, ver, fn = parsed
                logger.info("  Would check: %s %s (%s)", pkg, ver, fn)
            else:
                logger.warning("  Could not parse: %s", url)
        logger.info("Dry run complete. %d wheels would be checked.", len(to_check))
        await cache.close()
        return

    # Fetch PyPI metadata per package@version to get SHA-256 digests
    async with httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "pypi-tea-attestation/1.0 (https://github.com/sbomify/pypi-tea)"},
    ) as client:
        verified = 0
        not_available = 0
        failed = 0
        errors = 0

        # Group wheels by package@version for efficient metadata fetching
        pkg_ver_wheels: dict[str, list[str]] = {}
        unparseable: list[str] = []
        for url in to_check:
            parsed = parse_wheel_url(url)
            if parsed:
                pkg, ver, _fn = parsed
                key = f"{pkg}@{ver}"
                pkg_ver_wheels.setdefault(key, []).append(url)
            else:
                logger.warning("Could not parse wheel URL: %s", url)
                unparseable.append(url)

        total_groups = len(pkg_ver_wheels)
        for i, (key, urls) in enumerate(sorted(pkg_ver_wheels.items()), 1):
            pkg, ver = key.rsplit("@", 1)
            logger.info("[%d/%d] %s@%s (%d wheels)", i, total_groups, pkg, ver, len(urls))

            # Fetch PyPI metadata to get digests
            try:
                pypi_url = f"https://pypi.org/pypi/{pkg}/{ver}/json"
                resp = await client.get(pypi_url)
                if resp.status_code != 200:
                    logger.warning("  PyPI returned %d for %s@%s", resp.status_code, pkg, ver)
                    errors += len(urls)
                    continue
                metadata = resp.json()
            except httpx.HTTPError as e:
                logger.warning("  Failed to fetch metadata for %s@%s: %s", pkg, ver, e)
                errors += len(urls)
                continue

            # Build a lookup of filename → digests from PyPI metadata
            file_digests: dict[str, dict[str, str]] = {}
            file_sizes: dict[str, int | None] = {}
            for release_file in metadata.get("urls", []):
                fn = release_file.get("filename", "")
                file_digests[fn] = release_file.get("digests", {})
                file_sizes[fn] = release_file.get("size")

            for url in urls:
                filename = url.rsplit("/", 1)[-1] if "/" in url else url
                digests = file_digests.get(filename, {})
                size = file_sizes.get(filename)

                if not digests.get("sha256"):
                    logger.warning("  No SHA-256 digest for %s, skipping", filename)
                    errors += 1
                    continue

                wheel = WheelInfo(filename=filename, url=url, digests=digests, size=size)
                try:
                    result = await check_wheel_attestation(client, cache, pkg, ver, wheel)
                    if result.status == "verified":
                        verified += 1
                        logger.info("  %s: verified (publisher: %s)", filename, result.publisher_kind)
                    elif result.status == "not_available":
                        not_available += 1
                        logger.debug("  %s: not available", filename)
                    elif result.status == "failed":
                        failed += 1
                        logger.warning("  %s: failed (%s)", filename, result.error)
                    else:
                        logger.info("  %s: %s", filename, result.status)
                except Exception as e:
                    logger.error("  Error checking %s: %s", filename, e)
                    errors += 1

    await cache.close()

    logger.info(
        "Done! Verified: %d, Not available: %d, Failed: %d, Errors: %d, Unparseable: %d",
        verified,
        not_available,
        failed,
        errors,
        len(unparseable),
    )


if __name__ == "__main__":
    asyncio.run(main())

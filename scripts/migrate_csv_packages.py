#!/usr/bin/env python3
"""Populate Redis from a CSV of PyPI packages.

Reads a CSV file with columns: package, latest_version, has_provenance, has_attestation, has_sbom
and resolves each package@version through the normal TEA pipeline (metadata, SBOMs, attestations,
UUID lookups, stats tracking).

Usage:
    uv run python scripts/migrate_csv_packages.py ~/pypi_packages.csv

Options:
    --dry-run         Show what would be processed without making changes
    --limit N         Only process the first N packages (useful for testing)
    --offset N        Skip the first N packages (resume from a previous run)
    --concurrency N   Number of concurrent requests (default: 10)
    --sbom-only       Only process packages where has_sbom=t in the CSV
    --retry-errors    Retry packages that failed in a previous run (reads errors log)
    --log-file FILE   Write errors to a file for later retry (default: migrate_errors.log)

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).
"""

import argparse
import asyncio
import csv
import logging
import os
import sys
import time

# Allow importing from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx

from pypi_tea.cache import Cache
from pypi_tea.services.mapper import resolve_purl

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("migrate_csv")

REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")


def read_csv(path: str) -> list[dict[str, str]]:
    """Read the CSV file and return rows as dicts."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def read_error_log(path: str) -> list[tuple[str, str]]:
    """Read package@version pairs from an error log file."""
    pairs: list[tuple[str, str]] = []
    if not os.path.exists(path):
        return pairs
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "@" in line:
                name, _, version = line.partition("@")
                pairs.append((name, version))
    return pairs


async def process_package(
    sem: asyncio.Semaphore,
    client: httpx.AsyncClient,
    cache: Cache,
    name: str,
    version: str,
    index: int,
    total: int,
    error_file: str | None,
) -> bool:
    """Resolve a single package. Returns True on success."""
    async with sem:
        purl = f"pkg:pypi/{name}@{version}"
        try:
            await resolve_purl(client, cache, purl)
            logger.info("[%d/%d] OK %s@%s", index, total, name, version)
            return True
        except Exception as e:
            logger.error("[%d/%d] FAIL %s@%s: %s", index, total, name, version, e)
            if error_file:
                with open(error_file, "a") as f:
                    f.write(f"{name}@{version}\n")
            return False


async def main() -> None:
    parser = argparse.ArgumentParser(description="Populate Redis from a CSV of PyPI packages")
    parser.add_argument("csv_file", help="Path to the CSV file")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be processed")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of packages to process")
    parser.add_argument("--offset", type=int, default=0, help="Skip first N packages")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("--sbom-only", action="store_true", help="Only process packages with has_sbom=t")
    parser.add_argument("--retry-errors", action="store_true", help="Retry packages from error log")
    parser.add_argument("--log-file", default="migrate_errors.log", help="Error log file path")
    args = parser.parse_args()

    # Build the list of packages to process
    if args.retry_errors:
        pairs = read_error_log(args.log_file)
        if not pairs:
            logger.info("No errors to retry in %s", args.log_file)
            return
        logger.info("Retrying %d packages from %s", len(pairs), args.log_file)
        # Clear the error log since we're retrying
        os.rename(args.log_file, args.log_file + ".bak")
        packages = [{"name": name, "version": version} for name, version in pairs]
    else:
        logger.info("Reading CSV: %s", args.csv_file)
        rows = read_csv(args.csv_file)
        logger.info("Total rows in CSV: %d", len(rows))

        if args.sbom_only:
            rows = [r for r in rows if r.get("has_sbom") == "t"]
            logger.info("Filtered to %d packages with SBOMs", len(rows))

        packages = [{"name": r["package"], "version": r["latest_version"]} for r in rows]

    # Apply offset and limit
    if args.offset > 0:
        packages = packages[args.offset :]
        logger.info("Skipped first %d, %d remaining", args.offset, len(packages))

    if args.limit > 0:
        packages = packages[: args.limit]
        logger.info("Limited to %d packages", len(packages))

    total = len(packages)
    logger.info("Will process %d packages (concurrency=%d)", total, args.concurrency)

    if args.dry_run:
        for i, pkg in enumerate(packages[:20], 1):
            logger.info("  [%d] %s@%s", i, pkg["name"], pkg["version"])
        if total > 20:
            logger.info("  ... and %d more", total - 20)
        logger.info("Dry run complete.")
        return

    # Set up cache and HTTP client
    cache = Cache(REDIS_URL)
    await cache.init()

    sem = asyncio.Semaphore(args.concurrency)
    start_time = time.monotonic()

    async with httpx.AsyncClient(
        timeout=60.0,
        headers={"User-Agent": "pypi-tea-migrate/1.0 (https://github.com/sbomify/pypi-tea)"},
        limits=httpx.Limits(max_connections=args.concurrency + 5, max_keepalive_connections=args.concurrency),
    ) as client:
        tasks = [
            process_package(sem, client, cache, pkg["name"], pkg["version"], i, total, args.log_file)
            for i, pkg in enumerate(packages, 1)
        ]

        # Process in batches to avoid building up too many tasks at once
        batch_size = 1000
        success = 0
        errors = 0

        for batch_start in range(0, len(tasks), batch_size):
            batch = tasks[batch_start : batch_start + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            for result in results:
                if result is True:
                    success += 1
                else:
                    errors += 1

            elapsed = time.monotonic() - start_time
            processed = batch_start + len(batch)
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (total - processed) / rate if rate > 0 else 0
            logger.info(
                "Progress: %d/%d (%.1f%%) | OK: %d, Errors: %d | %.1f pkg/s | ETA: %.0fm",
                processed,
                total,
                processed / total * 100,
                success,
                errors,
                rate,
                eta / 60,
            )

    await cache.close()

    elapsed = time.monotonic() - start_time
    logger.info(
        "Done! Processed: %d, Success: %d, Errors: %d, Time: %.1fm",
        total,
        success,
        errors,
        elapsed / 60,
    )
    if errors > 0:
        logger.info("Failed packages logged to %s — rerun with --retry-errors to retry", args.log_file)


if __name__ == "__main__":
    asyncio.run(main())

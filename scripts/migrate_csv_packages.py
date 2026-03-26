#!/usr/bin/env python3
"""Populate Redis from a CSV of PyPI packages.

Reads a CSV file with columns: package, latest_version, has_provenance, has_attestation, has_sbom
and resolves each package@version through a lightweight pipeline that skips attestation checks
(use populate_attestations.py to backfill those separately).

For packages where has_sbom=f in the CSV, only metadata + UUID lookups are stored (no SBOM
extraction attempted), making those ~3x faster.

Usage:
    uv run python scripts/migrate_csv_packages.py ~/pypi_packages.csv

Options:
    --dry-run         Show what would be processed without making changes
    --limit N         Only process the first N packages (useful for testing)
    --offset N        Skip the first N packages (resume from a previous run)
    --concurrency N   Number of concurrent requests (default: 50)
    --sbom-only       Only process packages where has_sbom=t in the CSV
    --with-attestations  Also run attestation checks (slow, off by default)
    --retry-errors    Retry packages that failed in a previous run (reads errors log)
    --log-file FILE   Write errors to a file for later retry (default: migrate_errors.log)

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).
"""

import argparse
import asyncio
import csv
import hashlib
import logging
import os
import sys
import time
from typing import Any

# Allow importing from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx

from pypi_tea.cache import Cache
from pypi_tea.services.pypi import WheelInfo, extract_wheel_urls, get_version_metadata
from pypi_tea.services.sbom_extractor import extract_sboms
from pypi_tea.services.sbom_format import detect_sbom_format, validate_sbom
from pypi_tea.services.uuids import (
    artifact_uuid,
    component_release_uuid,
    component_uuid,
    product_release_uuid,
    product_uuid,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("migrate_csv")

# Suppress noisy httpx request logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")


def read_csv(path: str) -> list[dict[str, str]]:
    """Read the CSV file and return rows as dicts."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def read_error_log(path: str) -> list[tuple[str, str, bool]]:
    """Read package@version pairs from an error log file."""
    pairs: list[tuple[str, str, bool]] = []
    if not os.path.exists(path):
        return pairs
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "@" in line:
                rest, _, has_sbom_str = line.rpartition("|")
                if rest:
                    name, _, version = rest.partition("@")
                    pairs.append((name, version, has_sbom_str == "t"))
                else:
                    # Legacy format without has_sbom
                    name, _, version = line.partition("@")
                    pairs.append((name, version, False))
    return pairs


async def _store_uuid_lookups(
    cache: Cache, name: str, version: str, wheels: list[WheelInfo], sboms_by_wheel: dict[str, list[dict[str, Any]]]
) -> None:
    """Store UUID lookups for all entities in a single pipeline-friendly flow."""
    await cache.set_uuid_lookup(product_uuid(name), "product", {"name": name})
    await cache.set_uuid_lookup(
        product_release_uuid(name, version), "product_release", {"name": name, "version": version}
    )
    for wheel in wheels:
        await cache.set_uuid_lookup(
            component_uuid(wheel.filename), "component", {"filename": wheel.filename, "url": wheel.url}
        )
        await cache.set_uuid_lookup(
            component_release_uuid(wheel.url),
            "component_release",
            {"filename": wheel.filename, "url": wheel.url, "name": name, "version": version},
        )
        for sbom in sboms_by_wheel.get(wheel.url, []):
            await cache.set_uuid_lookup(
                artifact_uuid(wheel.url, sbom["path"]),
                "artifact",
                {"wheel_url": wheel.url, "sbom_path": sbom["path"], "name": name, "version": version},
            )


async def _track_sbom_formats(
    cache: Cache, wheel_url: str, sboms: list[dict[str, Any]], name: str, version: str
) -> None:
    """Track SBOM formats, validation, and encoding."""
    for sbom in sboms:
        content = sbom["content"]
        media_type = sbom["media_type"]
        fmt, _mt = detect_sbom_format(content)
        if fmt:
            sbom_id = f"{wheel_url}:{sbom['path']}"
            await cache.track_sbom_format(sbom_id, fmt)
            await cache.track_sbom_encoding(sbom_id, media_type)
            valid = validate_sbom(content, fmt, media_type)
            await cache.track_sbom_validation(sbom_id, valid)
            await cache.track_package_format(name, version, fmt)


async def resolve_package_light(
    client: httpx.AsyncClient,
    cache: Cache,
    name: str,
    version: str,
    skip_sbom_extraction: bool = False,
) -> None:
    """Lightweight resolve: metadata + SBOMs + UUID lookups. No attestation checks."""
    # Fetch PyPI metadata (with cache)
    cached_meta = await cache.get_pypi_metadata(name, version)
    if cached_meta:
        metadata = cached_meta
    else:
        metadata = await get_version_metadata(client, name, version)
        await cache.set_pypi_metadata(name, version, metadata)

    wheels = extract_wheel_urls(metadata)
    sboms_by_wheel: dict[str, list[dict[str, Any]]] = {}

    if not skip_sbom_extraction:
        for wheel in wheels:
            # Check negative cache first
            if await cache.is_negative_cached(wheel.url):
                continue
            # Check SBOM cache
            cached_sboms = await cache.get_sbom_content(wheel.url)
            if cached_sboms is not None:
                if cached_sboms:
                    sboms_by_wheel[wheel.url] = cached_sboms
                continue
            # Extract SBOMs from wheel
            sbom_files = await extract_sboms(wheel.url, wheel_size=wheel.size)
            if not sbom_files:
                await cache.set_negative_cache(wheel.url)
                continue
            result = [
                {
                    "path": s.path,
                    "content": s.content,
                    "media_type": s.media_type,
                    "sha256": hashlib.sha256(s.content.encode()).hexdigest(),
                }
                for s in sbom_files
            ]
            await cache.set_sbom_content(wheel.url, result)
            await _track_sbom_formats(cache, wheel.url, result, name, version)
            sboms_by_wheel[wheel.url] = result
    else:
        # Even when skipping extraction, set negative cache for all wheels
        # so future requests don't waste time trying
        for wheel in wheels:
            if not await cache.is_negative_cached(wheel.url):
                await cache.set_negative_cache(wheel.url)

    # Store UUID lookups
    await _store_uuid_lookups(cache, name, version, wheels, sboms_by_wheel)

    # Track package query
    has_sbom = bool(sboms_by_wheel)
    await cache.track_package_query(name, version, has_sbom=has_sbom)


async def process_package(
    sem: asyncio.Semaphore,
    client: httpx.AsyncClient,
    cache: Cache,
    name: str,
    version: str,
    has_sbom_hint: bool,
    index: int,
    total: int,
    error_file: str | None,
    with_attestations: bool = False,
) -> bool:
    """Resolve a single package. Returns True on success."""
    async with sem:
        try:
            if with_attestations:
                # Full pipeline including attestation
                from pypi_tea.services.mapper import resolve_purl

                purl = f"pkg:pypi/{name}@{version}"
                await resolve_purl(client, cache, purl)
            else:
                # Skip attestation, and skip SBOM extraction if CSV says no SBOMs
                await resolve_package_light(client, cache, name, version, skip_sbom_extraction=not has_sbom_hint)
            if index % 100 == 0 or index == total:
                logger.info("[%d/%d] OK %s@%s", index, total, name, version)
            return True
        except Exception as e:
            logger.error("[%d/%d] FAIL %s@%s: %s", index, total, name, version, e)
            if error_file:
                with open(error_file, "a") as f:
                    f.write(f"{name}@{version}|{'t' if has_sbom_hint else 'f'}\n")
            return False


async def main() -> None:
    parser = argparse.ArgumentParser(description="Populate Redis from a CSV of PyPI packages")
    parser.add_argument("csv_file", help="Path to the CSV file")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be processed")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of packages to process")
    parser.add_argument("--offset", type=int, default=0, help="Skip first N packages")
    parser.add_argument("--concurrency", type=int, default=50, help="Number of concurrent requests")
    parser.add_argument("--sbom-only", action="store_true", help="Only process packages with has_sbom=t")
    parser.add_argument("--with-attestations", action="store_true", help="Also check attestations (slow)")
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
        packages = [{"name": name, "version": version, "has_sbom": has_sbom} for name, version, has_sbom in pairs]
    else:
        logger.info("Reading CSV: %s", args.csv_file)
        rows = read_csv(args.csv_file)
        logger.info("Total rows in CSV: %d", len(rows))

        if args.sbom_only:
            rows = [r for r in rows if r.get("has_sbom") == "t"]
            logger.info("Filtered to %d packages with SBOMs", len(rows))

        packages = [
            {"name": r["package"], "version": r["latest_version"], "has_sbom": r.get("has_sbom") == "t"} for r in rows
        ]

    # Apply offset and limit
    if args.offset > 0:
        packages = packages[args.offset :]
        logger.info("Skipped first %d, %d remaining", args.offset, len(packages))

    if args.limit > 0:
        packages = packages[: args.limit]
        logger.info("Limited to %d packages", len(packages))

    total = len(packages)
    sbom_count = sum(1 for p in packages if p["has_sbom"])
    logger.info(
        "Will process %d packages (%d with SBOMs, %d without) concurrency=%d attestations=%s",
        total,
        sbom_count,
        total - sbom_count,
        args.concurrency,
        "on" if args.with_attestations else "off",
    )

    if args.dry_run:
        for i, pkg in enumerate(packages[:20], 1):
            sbom_flag = " [SBOM]" if pkg["has_sbom"] else ""
            logger.info("  [%d] %s@%s%s", i, pkg["name"], pkg["version"], sbom_flag)
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
        limits=httpx.Limits(max_connections=args.concurrency + 10, max_keepalive_connections=args.concurrency),
    ) as client:
        # Process in batches to avoid building up too many coroutines
        batch_size = 500
        success = 0
        errors = 0

        for batch_start in range(0, total, batch_size):
            batch_pkgs = packages[batch_start : batch_start + batch_size]
            tasks = [
                process_package(
                    sem,
                    client,
                    cache,
                    pkg["name"],
                    pkg["version"],
                    pkg["has_sbom"],
                    batch_start + i,
                    total,
                    args.log_file,
                    with_attestations=args.with_attestations,
                )
                for i, pkg in enumerate(batch_pkgs, 1)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if result is True:
                    success += 1
                else:
                    errors += 1

            elapsed = time.monotonic() - start_time
            processed = batch_start + len(batch_pkgs)
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

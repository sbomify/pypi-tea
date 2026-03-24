#!/usr/bin/env python3
"""Import pre-extracted SBOM dump into Redis.

Loads SBOM data from a CSV inventory + tarball into the pypi-tea Redis cache,
making all SBOMs immediately servable without on-demand extraction.

Two phases:
  1. Resolve wheel URLs from PyPI JSON API (cached to url_cache.json)
  2. Load SBOM content, UUID lookups, and tracking data into Redis

Run:
    uv run python scripts/import_sbom_dump.py \
        --csv ~/tmp/ben/sbom_inventory.csv \
        --tarball ~/tmp/ben/sbom_contents.tar.gz

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).
"""

import argparse
import asyncio
import csv
import hashlib
import json
import os
import sys
import tarfile
from dataclasses import dataclass, field

import httpx
import redis.asyncio as redis

# Allow importing from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pypi_tea.services.sbom_format import validate_sbom
from pypi_tea.services.uuids import (
    artifact_uuid,
    component_release_uuid,
    component_uuid,
    product_release_uuid,
    product_uuid,
)

REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")

# Redis key names (must match cache.py)
STATS_KEY = "stats"
UNIQUE_PACKAGES_WITH_SBOM = "unique:packages_with_sbom"
UNIQUE_WHEELS_WITH_SBOM = "unique:wheels_with_sbom"
UNIQUE_SBOM_FORMATS_TRACKED = "unique:sbom_formats_tracked"
UNIQUE_SBOM_ENCODINGS = "unique:sbom_encodings"
UNIQUE_SBOM_VALIDATION = "unique:sbom_validation"


@dataclass
class CsvRow:
    package_name: str
    version: str
    wheel_filename: str
    wheel_sha256: str
    wheel_md5: str
    wheel_size: int
    sbom_path: str
    sbom_tarball_path: str
    sbom_sha256: str
    sbom_media_type: str
    sbom_format: str
    sbom_size: int


@dataclass
class ImportStats:
    urls_resolved: int = 0
    urls_failed: int = 0
    urls_cached: int = 0
    sboms_imported: int = 0
    sboms_skipped: int = 0
    sha256_mismatches: int = 0
    tarball_missing: int = 0
    validated: int = 0
    valid: int = 0
    invalid: int = 0
    failed_packages: list[str] = field(default_factory=list)


def parse_csv(csv_path: str) -> list[CsvRow]:
    rows: list[CsvRow] = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(
                CsvRow(
                    package_name=row["package_name"],
                    version=row["version"],
                    wheel_filename=row["wheel_filename"],
                    wheel_sha256=row["wheel_sha256"],
                    wheel_md5=row["wheel_md5"],
                    wheel_size=int(row["wheel_size"]),
                    sbom_path=row["sbom_path"],
                    sbom_tarball_path=row["sbom_tarball_path"],
                    sbom_sha256=row["sbom_sha256"],
                    sbom_media_type=row["sbom_media_type"],
                    sbom_format=row["sbom_format"],
                    sbom_size=int(row["sbom_size"]),
                )
            )
    return rows


def load_url_cache(cache_path: str) -> dict[str, dict[str, str]]:
    """Load {package@version: {filename: url}} from cache file."""
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            return json.load(f)
    return {}


def save_url_cache(cache_path: str, cache: dict[str, dict[str, str]]) -> None:
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)


async def resolve_urls(
    rows: list[CsvRow],
    url_cache_path: str,
    concurrency: int,
    stats: ImportStats,
) -> dict[str, str]:
    """Resolve wheel filenames to full PyPI CDN URLs.

    Returns {wheel_filename: full_url}.
    """
    url_cache = load_url_cache(url_cache_path)

    # Collect unique (package, version) pairs
    pkg_versions: dict[str, set[str]] = {}
    for row in rows:
        key = f"{row.package_name}@{row.version}"
        if key not in pkg_versions:
            pkg_versions[key] = set()
        pkg_versions[key].add(row.wheel_filename)

    # Determine which need fetching
    to_fetch: list[tuple[str, str]] = []
    for key in pkg_versions:
        if key not in url_cache:
            name, version = key.rsplit("@", 1)
            to_fetch.append((name, version))
        else:
            stats.urls_cached += 1

    if to_fetch:
        print(f"Resolving URLs: {len(to_fetch)} package/versions to fetch ({stats.urls_cached} cached)")
    else:
        print(f"All {stats.urls_cached} package/version URLs already cached")

    sem = asyncio.Semaphore(concurrency)
    save_counter = 0

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:

        async def fetch_one(name: str, version: str) -> None:
            nonlocal save_counter
            key = f"{name}@{version}"
            async with sem:
                try:
                    resp = await client.get(f"https://pypi.org/pypi/{name}/{version}/json")
                    resp.raise_for_status()
                    data = resp.json()
                    # Extract filename -> url mapping for wheels
                    filename_to_url: dict[str, str] = {}
                    for url_info in data.get("urls", []):
                        fn = url_info.get("filename", "")
                        if fn.endswith(".whl"):
                            filename_to_url[fn] = url_info["url"]
                    url_cache[key] = filename_to_url
                    stats.urls_resolved += 1
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        print(f"  WARNING: {name}=={version} not found on PyPI (404)")
                        url_cache[key] = {}  # cache empty so we don't retry
                    else:
                        print(f"  ERROR: {name}=={version} HTTP {e.response.status_code}")
                    stats.urls_failed += 1
                    stats.failed_packages.append(key)
                except Exception as e:
                    print(f"  ERROR: {name}=={version}: {e}")
                    stats.urls_failed += 1
                    stats.failed_packages.append(key)

                save_counter += 1
                # Save cache periodically
                if save_counter % 50 == 0:
                    save_url_cache(url_cache_path, url_cache)
                    done = stats.urls_resolved + stats.urls_failed
                    total = len(to_fetch)
                    print(f"  Resolving URLs: {done}/{total} ({done * 100 // total}%)")

        tasks = [fetch_one(name, version) for name, version in to_fetch]
        await asyncio.gather(*tasks)

    # Final save
    save_url_cache(url_cache_path, url_cache)

    # Build flat filename -> url mapping
    filename_to_url: dict[str, str] = {}
    for _key, mapping in url_cache.items():
        for fn, url in mapping.items():
            filename_to_url[fn] = url

    return filename_to_url


async def load_into_redis(
    r: redis.Redis,
    rows: list[CsvRow],
    filename_to_url: dict[str, str],
    tarball_path: str,
    do_validate: bool,
    dry_run: bool,
    stats: ImportStats,
) -> None:
    """Load SBOM data into Redis."""
    # Open tarball and index members
    print("Reading tarball index...")
    tar_ctx = tarfile.open(tarball_path, "r:gz")  # noqa: SIM115
    tar = tar_ctx.__enter__()
    tar_members: dict[str, tarfile.TarInfo] = {}
    for member in tar.getmembers():
        tar_members[member.name] = member

    # Group rows by wheel_filename (some wheels have multiple SBOMs)
    wheels: dict[str, list[CsvRow]] = {}
    for row in rows:
        wheels.setdefault(row.wheel_filename, []).append(row)

    # Track stats for bulk write at end
    format_counts: dict[str, int] = {}
    encoding_counts: dict[str, int] = {}
    valid_count = 0
    invalid_count = 0

    total_wheels = len(wheels)
    processed = 0

    for wheel_filename, wheel_rows in wheels.items():
        processed += 1
        if processed % 200 == 0:
            print(f"  Loading SBOMs: {processed}/{total_wheels} wheels ({processed * 100 // total_wheels}%)")

        wheel_url = filename_to_url.get(wheel_filename)
        if not wheel_url:
            stats.sboms_skipped += len(wheel_rows)
            continue

        row0 = wheel_rows[0]
        name = row0.package_name
        version = row0.version

        # Read SBOM content from tarball and build the content array
        sbom_list: list[dict[str, str]] = []
        for row in wheel_rows:
            member = tar_members.get(row.sbom_tarball_path)
            if member is None:
                print(f"  WARNING: tarball missing {row.sbom_tarball_path}")
                stats.tarball_missing += 1
                continue

            f = tar.extractfile(member)
            if f is None:
                stats.tarball_missing += 1
                continue
            raw_bytes = f.read()
            f.close()

            # Compute SHA256 on raw bytes, then decode
            computed_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            content = raw_bytes.decode("utf-8", errors="replace")

            if computed_sha256 != row.sbom_sha256:
                stats.sha256_mismatches += 1

            sbom_entry = {
                "path": row.sbom_path,
                "content": content,
                "media_type": row.sbom_media_type,
                "sha256": row.sbom_sha256,
            }
            sbom_list.append(sbom_entry)

            # Track format/encoding
            sbom_id = f"{wheel_url}:{row.sbom_path}"
            fmt = row.sbom_format
            media_type = row.sbom_media_type
            format_counts[fmt] = format_counts.get(fmt, 0) + 1
            encoding_counts[media_type] = encoding_counts.get(media_type, 0) + 1

            if not dry_run:
                pipe = r.pipeline()
                pipe.hset(UNIQUE_SBOM_FORMATS_TRACKED, sbom_id, fmt)
                pipe.hset(UNIQUE_SBOM_ENCODINGS, sbom_id, media_type)
                await pipe.execute()

            # Optional validation
            if do_validate:
                valid = validate_sbom(content, fmt, media_type)
                result = "valid" if valid else "invalid"
                if valid:
                    valid_count += 1
                else:
                    invalid_count += 1
                stats.validated += 1
                if valid:
                    stats.valid += 1
                else:
                    stats.invalid += 1
                if not dry_run:
                    await r.hset(UNIQUE_SBOM_VALIDATION, sbom_id, result)

            stats.sboms_imported += 1

        if not sbom_list:
            continue

        if dry_run:
            continue

        # Write SBOM content (no TTL — permanent for imported data)
        await r.set(f"sbom:{wheel_url}", json.dumps(sbom_list))

        # Write tracking sets
        pipe = r.pipeline()
        pipe.sadd(UNIQUE_WHEELS_WITH_SBOM, wheel_url)
        pipe.sadd(UNIQUE_PACKAGES_WITH_SBOM, f"{name}@{version}")
        await pipe.execute()

        # Write UUID lookups
        prod_uuid = product_uuid(name)
        prod_rel_uuid = product_release_uuid(name, version)

        pipe = r.pipeline()
        # Product
        pipe.set(f"uuid:{prod_uuid}", json.dumps({"entity_type": "product", "name": name}))
        pipe.sadd("etype:product", prod_uuid)
        # Product Release
        pipe.set(
            f"uuid:{prod_rel_uuid}",
            json.dumps({"entity_type": "product_release", "name": name, "version": version}),
        )
        pipe.sadd("etype:product_release", prod_rel_uuid)
        # Component (wheel)
        comp_uuid = component_uuid(wheel_filename)
        pipe.set(
            f"uuid:{comp_uuid}",
            json.dumps({"entity_type": "component", "filename": wheel_filename, "url": wheel_url}),
        )
        pipe.sadd("etype:component", comp_uuid)
        # Component Release
        comp_rel_uuid = component_release_uuid(wheel_url)
        pipe.set(
            f"uuid:{comp_rel_uuid}",
            json.dumps(
                {
                    "entity_type": "component_release",
                    "filename": wheel_filename,
                    "url": wheel_url,
                    "name": name,
                    "version": version,
                }
            ),
        )
        pipe.sadd("etype:component_release", comp_rel_uuid)
        # Artifacts
        for sbom_entry in sbom_list:
            art_uuid = artifact_uuid(wheel_url, sbom_entry["path"])
            pipe.set(
                f"uuid:{art_uuid}",
                json.dumps(
                    {
                        "entity_type": "artifact",
                        "wheel_url": wheel_url,
                        "sbom_path": sbom_entry["path"],
                        "name": name,
                        "version": version,
                    }
                ),
            )
            pipe.sadd("etype:artifact", art_uuid)
        await pipe.execute()

    tar_ctx.__exit__(None, None, None)

    # Write aggregated stats counters
    if not dry_run:
        pipe = r.pipeline()
        for fmt, count in format_counts.items():
            pipe.hset(STATS_KEY, f"sbom_format:{fmt}", count)
        for mt, count in encoding_counts.items():
            pipe.hset(STATS_KEY, f"sbom_encoding:{mt}", count)
        if do_validate:
            pipe.hset(STATS_KEY, "sbom_validation:valid", valid_count)
            pipe.hset(STATS_KEY, "sbom_validation:invalid", invalid_count)
        await pipe.execute()


def print_summary(stats: ImportStats, do_validate: bool) -> None:
    print("\n=== Import Summary ===")
    print(f"URLs: {stats.urls_resolved} resolved, {stats.urls_cached} cached, {stats.urls_failed} failed")
    print(f"SBOMs: {stats.sboms_imported} imported, {stats.sboms_skipped} skipped")
    if stats.sha256_mismatches:
        print(f"SHA256 mismatches: {stats.sha256_mismatches}")
    if stats.tarball_missing:
        print(f"Tarball entries missing: {stats.tarball_missing}")
    if do_validate:
        print(f"Validation: {stats.valid} valid, {stats.invalid} invalid (of {stats.validated})")
    if stats.failed_packages:
        print(f"\nFailed packages ({len(stats.failed_packages)}):")
        for pkg in stats.failed_packages[:20]:
            print(f"  {pkg}")
        if len(stats.failed_packages) > 20:
            print(f"  ... and {len(stats.failed_packages) - 20} more")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Import SBOM dump into pypi-tea Redis")
    parser.add_argument("--csv", default=os.path.expanduser("~/tmp/ben/sbom_inventory.csv"), help="Path to CSV")
    parser.add_argument(
        "--tarball", default=os.path.expanduser("~/tmp/ben/sbom_contents.tar.gz"), help="Path to tarball"
    )
    parser.add_argument("--url-cache", default=None, help="Path to URL cache JSON (default: next to tarball)")
    parser.add_argument("--concurrency", type=int, default=10, help="PyPI API concurrency")
    parser.add_argument("--dry-run", action="store_true", help="Resolve URLs only, skip Redis writes")
    parser.add_argument("--validate", action="store_true", help="Run SBOM validation (slow)")
    args = parser.parse_args()

    if args.url_cache is None:
        args.url_cache = os.path.join(os.path.dirname(args.tarball), "url_cache.json")

    stats = ImportStats()

    # Phase 0: Parse CSV
    print(f"Parsing CSV: {args.csv}")
    rows = parse_csv(args.csv)
    print(f"  {len(rows)} rows")

    # Phase 1: Resolve URLs
    filename_to_url = await resolve_urls(rows, args.url_cache, args.concurrency, stats)

    # Check coverage
    needed = {row.wheel_filename for row in rows}
    resolved = needed & set(filename_to_url.keys())
    missing = needed - resolved
    print(f"URL coverage: {len(resolved)}/{len(needed)} wheel filenames resolved")
    if missing:
        print(f"  {len(missing)} filenames could not be resolved")

    # Phase 2: Load into Redis
    if args.dry_run:
        print("\n[DRY RUN] Skipping Redis writes")
        # For dry run, we still parse tarball to verify data
        print("Verifying tarball data...")
        await load_into_redis(None, rows, filename_to_url, args.tarball, args.validate, True, stats)  # type: ignore[arg-type]
    else:
        print(f"\nConnecting to Redis: {REDIS_URL}")
        r = redis.from_url(REDIS_URL, decode_responses=True)
        await load_into_redis(r, rows, filename_to_url, args.tarball, args.validate, False, stats)
        await r.aclose()

    print_summary(stats, args.validate)


if __name__ == "__main__":
    asyncio.run(main())

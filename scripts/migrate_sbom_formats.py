#!/usr/bin/env python3
"""One-off migration: rebuild SBOM format, validation, and encoding stats.

This script:
1. Deletes old tracking hashes (if present)
2. Clears stale counters from the stats hash
3. Rebuilds all counts by re-detecting and validating from cached SBOM content

Run once after deploying:
    uv run python scripts/migrate_sbom_formats.py

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).
"""

import asyncio
import json
import os
import sys

import redis.asyncio as redis

# Allow importing from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pypi_tea.services.sbom_format import detect_sbom_format, validate_sbom  # noqa: E402


REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")
STATS_KEY = "stats"
FORMATS_KEY = "unique:sbom_formats_tracked"
VALIDATION_KEY = "unique:sbom_validation"
ENCODINGS_KEY = "unique:sbom_encodings"
WHEELS_WITH_SBOM_KEY = "unique:wheels_with_sbom"


async def main() -> None:
    r = redis.from_url(REDIS_URL, decode_responses=True)

    # Step 1: Clear old tracking hashes
    for key_name, label in [
        (FORMATS_KEY, "format"),
        (VALIDATION_KEY, "validation"),
        (ENCODINGS_KEY, "encoding"),
    ]:
        key_type = await r.type(key_name)
        if key_type in ("set", "hash"):
            count = await r.hlen(key_name) if key_type == "hash" else await r.scard(key_name)
            print(f"Clearing {label} tracker ({count} entries)...")
            await r.delete(key_name)
        else:
            print(f"No existing {label} tracker found.")

    # Step 2: Clear stale counters
    raw = await r.hgetall(STATS_KEY)
    stale_keys = [k for k in raw if k.startswith(("sbom_format:", "sbom_validation:", "sbom_encoding:"))]
    if stale_keys:
        print(f"Clearing {len(stale_keys)} stale counters")
        await r.hdel(STATS_KEY, *stale_keys)

    # Step 3: Rebuild from cached SBOM content
    wheel_urls: set[str] = await r.smembers(WHEELS_WITH_SBOM_KEY)  # type: ignore[assignment]
    print(f"Wheels in tracking set: {len(wheel_urls)}")

    # Also scan for sbom:* keys directly
    scan_count = 0
    async for key in r.scan_iter(match="sbom:*", count=500):
        wheel_url = key.removeprefix("sbom:")
        if wheel_url not in wheel_urls:
            wheel_urls.add(wheel_url)
            await r.sadd(WHEELS_WITH_SBOM_KEY, wheel_url)  # type: ignore[misc]
            scan_count += 1
    if scan_count:
        print(f"Found {scan_count} additional wheels from sbom:* keys (added to tracking set)")
    print(f"Rebuilding from {len(wheel_urls)} total cached wheels...")

    format_counts: dict[str, int] = {}
    encoding_counts: dict[str, int] = {}
    valid_count = 0
    invalid_count = 0
    tracked = 0
    missing = 0

    for wheel_url in wheel_urls:
        cached = await r.get(f"sbom:{wheel_url}")
        if cached is None:
            missing += 1
            continue

        sboms = json.loads(cached)
        for sbom in sboms:
            sbom_id = f"{wheel_url}:{sbom['path']}"
            content = sbom["content"]
            media_type = sbom.get("media_type", "application/octet-stream")
            fmt, detected_mt = detect_sbom_format(content)
            if detected_mt:
                media_type = detected_mt
            if fmt:
                await r.hset(FORMATS_KEY, sbom_id, fmt)  # type: ignore[misc]
                await r.hset(ENCODINGS_KEY, sbom_id, media_type)  # type: ignore[misc]
                format_counts[fmt] = format_counts.get(fmt, 0) + 1
                encoding_counts[media_type] = encoding_counts.get(media_type, 0) + 1

                valid = validate_sbom(content, fmt, media_type)
                result = "valid" if valid else "invalid"
                await r.hset(VALIDATION_KEY, sbom_id, result)  # type: ignore[misc]
                if valid:
                    valid_count += 1
                else:
                    invalid_count += 1

                tracked += 1

    # Step 4: Write rebuilt counters to stats
    pipe = r.pipeline()
    for fmt, count in format_counts.items():
        pipe.hset(STATS_KEY, f"sbom_format:{fmt}", count)
    for mt, count in encoding_counts.items():
        pipe.hset(STATS_KEY, f"sbom_encoding:{mt}", count)
    pipe.hset(STATS_KEY, "sbom_validation:valid", valid_count)
    pipe.hset(STATS_KEY, "sbom_validation:invalid", invalid_count)
    await pipe.execute()

    print(f"\nDone! Tracked {tracked} SBOMs ({missing} wheels had expired cache).")
    print("\nFormat counts:")
    for fmt, count in sorted(format_counts.items()):
        print(f"  {fmt}: {count}")
    print(f"\nValidation: {valid_count} valid, {invalid_count} invalid")
    print("\nEncoding counts:")
    for mt, count in sorted(encoding_counts.items()):
        print(f"  {mt}: {count}")

    await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())

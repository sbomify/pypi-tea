#!/usr/bin/env python3
"""One-off migration: convert SBOM format tracking from set to hash map.

The old code used a Redis set for dedup + stat counters.
The new code uses a hash map (sbom_id → format) which is self-correcting.

This script:
1. Deletes the old set (if present)
2. Clears stale sbom_format:* counters from the stats hash
3. Rebuilds format counts by re-detecting formats from cached SBOM content

Run once after deploying v0.1.6+:
    uv run python scripts/migrate_sbom_formats.py

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).
"""

import asyncio
import json
import os

import redis.asyncio as redis


REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")
STATS_KEY = "stats"
FORMATS_KEY = "unique:sbom_formats_tracked"
WHEELS_WITH_SBOM_KEY = "unique:wheels_with_sbom"

SBOM_MEDIA_TYPES = {
    ".cdx.json": "application/vnd.cyclonedx+json",
    ".cdx.xml": "application/vnd.cyclonedx+xml",
    ".spdx.json": "application/spdx+json",
    ".spdx.rdf": "application/spdx+rdf",
    ".json": "application/json",
    ".xml": "application/xml",
    ".spdx": "text/spdx",
}


def guess_media_type(path: str) -> str:
    lower = path.lower()
    for suffix, mt in SBOM_MEDIA_TYPES.items():
        if lower.endswith(suffix):
            return mt
    return "application/octet-stream"


def detect_format(content: str, media_type: str) -> str | None:
    if "cyclonedx" in media_type:
        try:
            data = json.loads(content)
            return f"CycloneDX/{data.get('specVersion', 'unknown')}"
        except Exception:
            return "CycloneDX/unknown"
    if "spdx" in media_type:
        try:
            data = json.loads(content)
            version = data.get("spdxVersion", "").removeprefix("SPDX-") or "unknown"
            return f"SPDX/{version}"
        except Exception:
            return "SPDX/unknown"
    if media_type == "application/json":
        try:
            data = json.loads(content)
            if data.get("bomFormat") == "CycloneDX":
                return f"CycloneDX/{data.get('specVersion', 'unknown')}"
            if "spdxVersion" in data:
                return f"SPDX/{data['spdxVersion'].removeprefix('SPDX-')}"
        except Exception:
            pass
    return None


async def main() -> None:
    r = redis.from_url(REDIS_URL, decode_responses=True)

    # Step 1: Delete old set if present
    key_type = await r.type(FORMATS_KEY)
    if key_type == "set":
        count = await r.scard(FORMATS_KEY)
        print(f"Deleting old set-based format tracker ({count} entries)...")
        await r.delete(FORMATS_KEY)
    elif key_type == "hash":
        old_count = await r.hlen(FORMATS_KEY)
        print(f"Format tracker is already a hash ({old_count} entries). Clearing for rebuild...")
        await r.delete(FORMATS_KEY)
    else:
        print("No existing format tracker found.")

    # Step 2: Clear stale format counters
    raw = await r.hgetall(STATS_KEY)
    stale_keys = [k for k in raw if k.startswith("sbom_format:")]
    if stale_keys:
        print(f"Clearing {len(stale_keys)} stale format counters: {stale_keys}")
        await r.hdel(STATS_KEY, *stale_keys)

    # Step 3: Rebuild from cached SBOM content
    # Use both the tracking set AND a scan of sbom:* keys to catch any
    # wheels that were cached but not added to the set.
    wheel_urls: set[str] = await r.smembers(WHEELS_WITH_SBOM_KEY)  # type: ignore[assignment]
    print(f"Wheels in tracking set: {len(wheel_urls)}")

    # Also scan for sbom:* keys directly
    scan_count = 0
    async for key in r.scan_iter(match="sbom:*", count=500):
        wheel_url = key.removeprefix("sbom:")
        if wheel_url not in wheel_urls:
            wheel_urls.add(wheel_url)
            # Fix the tracking set while we're at it
            await r.sadd(WHEELS_WITH_SBOM_KEY, wheel_url)  # type: ignore[misc]
            scan_count += 1
    if scan_count:
        print(f"Found {scan_count} additional wheels from sbom:* keys (added to tracking set)")
    print(f"Rebuilding formats from {len(wheel_urls)} total cached wheels...")

    format_counts: dict[str, int] = {}
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
            media_type = sbom.get("media_type", guess_media_type(sbom["path"]))
            fmt = detect_format(sbom["content"], media_type)
            if fmt:
                await r.hset(FORMATS_KEY, sbom_id, fmt)  # type: ignore[misc]
                format_counts[fmt] = format_counts.get(fmt, 0) + 1
                tracked += 1

    # Step 4: Write rebuilt counters to stats
    pipe = r.pipeline()
    for fmt, count in format_counts.items():
        pipe.hset(STATS_KEY, f"sbom_format:{fmt}", count)
    await pipe.execute()

    print(f"\nDone! Tracked {tracked} SBOMs ({missing} wheels had expired cache).")
    print("Format counts:")
    for fmt, count in sorted(format_counts.items()):
        print(f"  {fmt}: {count}")

    await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())

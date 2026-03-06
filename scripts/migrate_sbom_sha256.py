#!/usr/bin/env python3
"""One-off migration: backfill SHA256 checksums into cached SBOM entries.

This script:
1. Scans all sbom:* keys in Redis
2. For each cached SBOM list, checks if entries already have "sha256"
3. If not, computes hashlib.sha256(content.encode()).hexdigest() and updates the cached JSON

Run once after deploying 0.2.5:
    uv run python scripts/migrate_sbom_sha256.py

Requires PYPI_TEA_REDIS_URL env var (defaults to redis://localhost:6379).
"""

import asyncio
import hashlib
import json
import os

import redis.asyncio as redis


REDIS_URL = os.environ.get("PYPI_TEA_REDIS_URL", "redis://localhost:6379")


async def main() -> None:
    r = redis.from_url(REDIS_URL, decode_responses=True)

    updated = 0
    skipped = 0
    total_keys = 0

    async for key in r.scan_iter(match="sbom:*", count=500):
        total_keys += 1
        cached = await r.get(key)
        if cached is None:
            continue

        sboms = json.loads(cached)
        needs_update = False

        for sbom in sboms:
            if "sha256" not in sbom:
                sbom["sha256"] = hashlib.sha256(sbom["content"].encode()).hexdigest()
                needs_update = True

        if needs_update:
            ttl = await r.ttl(key)
            await r.set(key, json.dumps(sboms))
            if ttl > 0:
                await r.expire(key, ttl)
            updated += 1
        else:
            skipped += 1

    print(f"Scanned {total_keys} sbom:* keys")
    print(f"Updated: {updated}")
    print(f"Skipped (already had sha256): {skipped}")

    await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())

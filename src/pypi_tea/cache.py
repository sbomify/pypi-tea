import json
import time
from typing import Any

import redis.asyncio as redis

PYPI_TTL = 3600  # 1 hour
SBOM_TTL = 86400  # 24 hours
NEGATIVE_TTL = 86400  # 24 hours

STATS_KEY = "stats"
STATS_BUCKET_PREFIX = "stats:ts:"
STATS_BUCKET_SIZE = 86400  # 24 hours
STATS_RETENTION = 86400 * 30  # 30 days

# Persistent sets for accurate unique counting (no TTL)
UNIQUE_PACKAGES = "unique:packages"
UNIQUE_PACKAGES_WITH_SBOM = "unique:packages_with_sbom"
UNIQUE_WHEELS_WITH_SBOM = "unique:wheels_with_sbom"
UNIQUE_WHEELS_WITHOUT_SBOM = "unique:wheels_without_sbom"
UNIQUE_SBOM_FORMATS_TRACKED = "unique:sbom_formats_tracked"

# Daily set prefixes for time series (with TTL)
DAILY_PACKAGES_PREFIX = "daily:packages:"
DAILY_PACKAGES_WITH_SBOM_PREFIX = "daily:packages_with_sbom:"


def _current_bucket() -> int:
    return int(time.time()) // STATS_BUCKET_SIZE * STATS_BUCKET_SIZE


class Cache:
    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._r: redis.Redis | None = None

    async def init(self) -> None:
        self._r = redis.from_url(self._redis_url, decode_responses=True)

    async def close(self) -> None:
        if self._r:
            await self._r.aclose()

    @property
    def _client(self) -> redis.Redis:
        assert self._r is not None
        return self._r

    async def _incr_stat(self, field: str) -> None:
        bucket = _current_bucket()
        bucket_key = f"{STATS_BUCKET_PREFIX}{bucket}"
        pipe = self._client.pipeline()
        pipe.hincrby(STATS_KEY, field, 1)
        pipe.hincrby(bucket_key, field, 1)
        pipe.expire(bucket_key, STATS_RETENTION)
        await pipe.execute()

    # --- PyPI metadata ---

    async def get_pypi_metadata(self, package: str, version: str) -> dict[str, Any] | None:
        data = await self._client.get(f"pypi:{package}:{version}")
        if data is None:
            await self._incr_stat("pypi:miss")
            return None
        await self._incr_stat("pypi:hit")
        return json.loads(data)  # type: ignore[no-any-return]

    async def set_pypi_metadata(self, package: str, version: str, data: dict[str, Any]) -> None:
        await self._client.set(f"pypi:{package}:{version}", json.dumps(data), ex=PYPI_TTL)

    # --- SBOM content ---

    async def get_sbom_content(self, wheel_url: str) -> list[dict[str, Any]] | None:
        data = await self._client.get(f"sbom:{wheel_url}")
        if data is None:
            await self._incr_stat("sbom:miss")
            return None
        await self._incr_stat("sbom:hit")
        return json.loads(data)  # type: ignore[no-any-return]

    async def set_sbom_content(self, wheel_url: str, sboms: list[dict[str, Any]]) -> None:
        await self._client.set(f"sbom:{wheel_url}", json.dumps(sboms), ex=SBOM_TTL)
        await self._client.sadd(UNIQUE_WHEELS_WITH_SBOM, wheel_url)  # type: ignore[misc]

    # --- Negative cache ---

    async def is_negative_cached(self, wheel_url: str) -> bool:
        exists = bool(await self._client.exists(f"neg:{wheel_url}"))
        if exists:
            await self._incr_stat("negative:hit")
        else:
            await self._incr_stat("negative:miss")
        return exists

    async def set_negative_cache(self, wheel_url: str) -> None:
        await self._client.set(f"neg:{wheel_url}", "1", ex=NEGATIVE_TTL)
        await self._client.sadd(UNIQUE_WHEELS_WITHOUT_SBOM, wheel_url)  # type: ignore[misc]

    # --- SBOM format tracking ---

    async def track_sbom_format(self, sbom_id: str, format_key: str) -> None:
        """Track SBOM format for a unique SBOM file. Deduplicates via persistent set."""
        is_new = await self._client.sadd(UNIQUE_SBOM_FORMATS_TRACKED, sbom_id)  # type: ignore[misc]
        if is_new:
            await self._incr_stat(f"sbom_format:{format_key}")

    # --- Package-level tracking ---

    async def track_package_query(self, package: str, version: str, has_sbom: bool) -> None:
        """Track a unique package@version query for community-facing stats."""
        key = f"{package}@{version}"
        bucket = _current_bucket()
        pipe = self._client.pipeline()
        pipe.sadd(UNIQUE_PACKAGES, key)
        daily_key = f"{DAILY_PACKAGES_PREFIX}{bucket}"
        pipe.sadd(daily_key, key)
        pipe.expire(daily_key, STATS_RETENTION)
        if has_sbom:
            pipe.sadd(UNIQUE_PACKAGES_WITH_SBOM, key)
            daily_sbom_key = f"{DAILY_PACKAGES_WITH_SBOM_PREFIX}{bucket}"
            pipe.sadd(daily_sbom_key, key)
            pipe.expire(daily_sbom_key, STATS_RETENTION)
        await pipe.execute()

    # --- UUID lookup ---

    async def get_uuid_lookup(self, uuid: str) -> dict[str, Any] | None:
        data = await self._client.get(f"uuid:{uuid}")
        if data is None:
            return None
        return json.loads(data)  # type: ignore[no-any-return]

    async def set_uuid_lookup(self, uuid: str, entity_type: str, data: dict[str, Any]) -> None:
        payload = {"entity_type": entity_type, **data}
        await self._client.set(f"uuid:{uuid}", json.dumps(payload))
        await self._client.sadd(f"etype:{entity_type}", uuid)  # type: ignore[misc]

    async def find_by_entity_type_and_field(self, entity_type: str, field: str, value: str) -> list[dict[str, Any]]:
        uuids = await self._client.smembers(f"etype:{entity_type}")  # type: ignore[misc]
        if not uuids:
            return []
        results: list[dict[str, Any]] = []
        pipe = self._client.pipeline()
        uuid_list = sorted(uuids)
        for uuid in uuid_list:
            pipe.get(f"uuid:{uuid}")
        values = await pipe.execute()
        for uuid, raw in zip(uuid_list, values, strict=True):
            if raw is None:
                continue
            data: dict[str, Any] = json.loads(raw)
            if data.get(field) == value:
                results.append({"uuid": uuid, **data})
        return results

    async def list_by_entity_type(
        self, entity_type: str, offset: int = 0, limit: int = 100
    ) -> tuple[list[dict[str, Any]], int]:
        uuids = await self._client.smembers(f"etype:{entity_type}")  # type: ignore[misc]
        total = len(uuids)
        if not uuids:
            return [], 0
        uuid_list = sorted(uuids)[offset : offset + limit]
        if not uuid_list:
            return [], total
        pipe = self._client.pipeline()
        for uuid in uuid_list:
            pipe.get(f"uuid:{uuid}")
        values = await pipe.execute()
        results: list[dict[str, Any]] = []
        for uuid, raw in zip(uuid_list, values, strict=True):
            if raw is not None:
                data: dict[str, Any] = json.loads(raw)
                results.append({"uuid": uuid, **data})
        return results, total

    # --- Statistics ---

    @staticmethod
    def _extract_sbom_formats(counters: dict[str, int]) -> dict[str, int]:
        return {k.removeprefix("sbom_format:"): v for k, v in counters.items() if k.startswith("sbom_format:")}

    async def get_stats(self) -> dict[str, Any]:
        raw = await self._client.hgetall(STATS_KEY)  # type: ignore[misc]
        counters: dict[str, int] = {k: int(v) for k, v in raw.items()}

        pipe = self._client.pipeline()
        pipe.scard(UNIQUE_PACKAGES)
        pipe.scard(UNIQUE_PACKAGES_WITH_SBOM)
        pipe.scard(UNIQUE_WHEELS_WITH_SBOM)
        pipe.scard(UNIQUE_WHEELS_WITHOUT_SBOM)
        pkg_total, pkg_with_sbom, wheels_with, wheels_without = await pipe.execute()

        wheels_total = wheels_with + wheels_without

        return {
            "packages": {
                "total_explored": pkg_total,
                "with_sbom": pkg_with_sbom,
                "without_sbom": pkg_total - pkg_with_sbom,
                "sbom_percentage": round(pkg_with_sbom / pkg_total * 100, 2) if pkg_total else None,
            },
            "wheels": {
                "total_checked": wheels_total,
                "with_sbom": wheels_with,
                "without_sbom": wheels_without,
                "sbom_percentage": round(wheels_with / wheels_total * 100, 2) if wheels_total else None,
            },
            "sbom_formats": self._extract_sbom_formats(counters),
        }

    async def get_stats_timeseries(self) -> list[dict[str, Any]]:
        now = int(time.time())
        oldest = now - STATS_RETENTION
        oldest_bucket = oldest // STATS_BUCKET_SIZE * STATS_BUCKET_SIZE
        current = _current_bucket()

        bucket_times: list[int] = []
        t = oldest_bucket
        while t <= current:
            bucket_times.append(t)
            t += STATS_BUCKET_SIZE

        if not bucket_times:
            return []

        pipe = self._client.pipeline()
        for bt in bucket_times:
            pipe.scard(f"{DAILY_PACKAGES_PREFIX}{bt}")
            pipe.scard(f"{DAILY_PACKAGES_WITH_SBOM_PREFIX}{bt}")
            pipe.hgetall(f"{STATS_BUCKET_PREFIX}{bt}")
        results = await pipe.execute()

        series: list[dict[str, Any]] = []
        for i, bt in enumerate(bucket_times):
            pkg_new = results[i * 3]
            pkg_with_sbom_new = results[i * 3 + 1]
            raw = results[i * 3 + 2]

            if not pkg_new and not raw:
                continue

            counters: dict[str, int] = {k: int(v) for k, v in raw.items()} if raw else {}

            series.append(
                {
                    "timestamp": bt,
                    "packages": {
                        "new_explored": pkg_new,
                        "new_with_sbom": pkg_with_sbom_new,
                    },
                    "sbom_formats": self._extract_sbom_formats(counters),
                }
            )
        return series

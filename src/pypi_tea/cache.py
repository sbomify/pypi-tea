import json
import time
from typing import Any

import redis.asyncio as redis

PYPI_TTL = 3600  # 1 hour
SBOM_TTL = 86400  # 24 hours
NEGATIVE_TTL = 86400  # 24 hours

STATS_KEY = "stats"
STATS_BUCKET_PREFIX = "stats:ts:"
STATS_BUCKET_SIZE = 300  # 5 minutes
STATS_RETENTION = 86400  # 24 hours


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
        await self._incr_stat("sbom:wheels_with_sbom")

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
        await self._incr_stat("sbom:wheels_without_sbom")

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

    async def find_by_entity_type_and_field(
        self, entity_type: str, field: str, value: str
    ) -> list[dict[str, Any]]:
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

    def _build_summary(self, counters: dict[str, int]) -> dict[str, Any]:
        pypi_hit = counters.get("pypi:hit", 0)
        pypi_miss = counters.get("pypi:miss", 0)
        pypi_total = pypi_hit + pypi_miss

        sbom_hit = counters.get("sbom:hit", 0)
        sbom_miss = counters.get("sbom:miss", 0)
        sbom_total = sbom_hit + sbom_miss

        neg_hit = counters.get("negative:hit", 0)
        neg_miss = counters.get("negative:miss", 0)
        neg_total = neg_hit + neg_miss

        wheels_with = counters.get("sbom:wheels_with_sbom", 0)
        wheels_without = counters.get("sbom:wheels_without_sbom", 0)
        wheels_total = wheels_with + wheels_without

        return {
            "cache": {
                "pypi_metadata": {
                    "hits": pypi_hit,
                    "misses": pypi_miss,
                    "hit_ratio": round(pypi_hit / pypi_total, 4) if pypi_total else None,
                },
                "sbom_content": {
                    "hits": sbom_hit,
                    "misses": sbom_miss,
                    "hit_ratio": round(sbom_hit / sbom_total, 4) if sbom_total else None,
                },
                "negative_cache": {
                    "hits": neg_hit,
                    "misses": neg_miss,
                    "hit_ratio": round(neg_hit / neg_total, 4) if neg_total else None,
                },
            },
            "sbom_availability": {
                "wheels_with_sbom": wheels_with,
                "wheels_without_sbom": wheels_without,
                "total_wheels_checked": wheels_total,
                "sbom_percentage": round(wheels_with / wheels_total * 100, 2) if wheels_total else None,
            },
        }

    async def get_stats(self) -> dict[str, Any]:
        raw = await self._client.hgetall(STATS_KEY)  # type: ignore[misc]
        counters: dict[str, int] = {k: int(v) for k, v in raw.items()}
        return self._build_summary(counters)

    async def get_stats_timeseries(self) -> list[dict[str, Any]]:
        now = int(time.time())
        oldest = now - STATS_RETENTION
        oldest_bucket = oldest // STATS_BUCKET_SIZE * STATS_BUCKET_SIZE
        current = _current_bucket()

        # Collect all bucket keys to fetch
        bucket_times: list[int] = []
        t = oldest_bucket
        while t <= current:
            bucket_times.append(t)
            t += STATS_BUCKET_SIZE

        if not bucket_times:
            return []

        pipe = self._client.pipeline()
        for bt in bucket_times:
            pipe.hgetall(f"{STATS_BUCKET_PREFIX}{bt}")
        results = await pipe.execute()

        series: list[dict[str, Any]] = []
        for bt, raw in zip(bucket_times, results, strict=True):
            if not raw:
                continue
            counters: dict[str, int] = {k: int(v) for k, v in raw.items()}
            series.append({
                "timestamp": bt,
                **self._build_summary(counters),
            })
        return series

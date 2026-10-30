from typing import Any

from fastapi import APIRouter

from pypi_tea import store
from pypi_tea.lookup import memoized

router = APIRouter()

# Aggregates scan whole tables; compute them at most this often per process.
STATS_TTL = 60.0


@router.get("/stats")
async def get_stats() -> Any:
    return await memoized("stats", STATS_TTL, store.stats)


@router.get("/stats/timeseries")
async def get_stats_timeseries() -> Any:
    return await memoized("stats:timeseries", STATS_TTL, store.stats_timeseries)


@router.get("/stats/usage")
async def get_usage_stats() -> Any:
    return await memoized("stats:usage", STATS_TTL, store.usage_stats)


@router.get("/stats/invalid-sboms")
async def get_invalid_sboms() -> Any:
    return await memoized("stats:invalid", STATS_TTL, store.invalid_sboms)

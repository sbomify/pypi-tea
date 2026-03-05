from typing import Any

from fastapi import APIRouter, Depends

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache

router = APIRouter()


@router.get("/stats")
async def get_stats(
    cache: Cache = Depends(get_cache),
) -> Any:
    return await cache.get_stats()


@router.get("/stats/timeseries")
async def get_stats_timeseries(
    cache: Cache = Depends(get_cache),
) -> Any:
    return await cache.get_stats_timeseries()

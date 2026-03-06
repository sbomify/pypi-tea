from typing import Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from libtea.models import ErrorResponse, ErrorType

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.serialization import tea_dump
from pypi_tea.services.mapper import (
    _get_metadata_cached,
    _get_sboms_for_wheel,
    build_component_release_with_collection,
)
from pypi_tea.services.pypi import WheelInfo, extract_wheel_urls

router = APIRouter()

_404 = ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True)


async def _resolve_component_release(
    uuid: str, client: httpx.AsyncClient, cache: Cache
) -> tuple[WheelInfo, str, dict[str, Any], list[dict[str, Any]]] | None:
    lookup = await cache.get_uuid_lookup(uuid)
    if not lookup or lookup["entity_type"] != "component_release":
        return None

    name, version = lookup["name"], lookup["version"]
    metadata = await _get_metadata_cached(client, cache, name, version)
    wheels = extract_wheel_urls(metadata)
    matching_wheel = next((w for w in wheels if w.filename == lookup["filename"]), None)
    if not matching_wheel:
        return None

    sboms = await _get_sboms_for_wheel(cache, matching_wheel)
    return matching_wheel, version, metadata, sboms


@router.get("/componentRelease/{uuid}")
async def get_component_release(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    result = await _resolve_component_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    wheel, version, metadata, sboms = result
    cr = build_component_release_with_collection(wheel, version, metadata, sboms)
    return tea_dump(cr)


@router.get("/componentRelease/{uuid}/collection/latest")
async def get_component_release_collection_latest(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    result = await _resolve_component_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    wheel, version, metadata, sboms = result
    cr = build_component_release_with_collection(wheel, version, metadata, sboms)
    return tea_dump(cr.latest_collection)


@router.get("/componentRelease/{uuid}/collections")
async def get_component_release_collections(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    result = await _resolve_component_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    wheel, version, metadata, sboms = result
    cr = build_component_release_with_collection(wheel, version, metadata, sboms)
    return [tea_dump(cr.latest_collection)]


@router.get("/componentRelease/{uuid}/collection/{coll_version}")
async def get_component_release_collection_version(
    uuid: str,
    coll_version: int,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    if coll_version != 1:
        return JSONResponse(status_code=404, content=_404)
    result = await _resolve_component_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    wheel, version, metadata, sboms = result
    cr = build_component_release_with_collection(wheel, version, metadata, sboms)
    return tea_dump(cr.latest_collection)

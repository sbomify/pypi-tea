from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from libtea.models import ErrorResponse, ErrorType, IdentifierType
from libtea.server import tea_datetime_serializer

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.serialization import tea_dump
from pypi_tea.services.mapper import (
    _get_sboms_for_wheel,
    build_collection_for_product_release,
    build_product_release,
    resolve_purl,
)
from pypi_tea.services.pypi import WheelInfo, extract_wheel_urls, get_version_metadata

router = APIRouter()

_404 = ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True)


@router.get("/productReleases")
async def list_or_search_product_releases(
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
    idType: str | None = Query(None),
    idValue: str | None = Query(None),
    pageOffset: int = Query(0, ge=0),
    pageSize: int = Query(100, ge=1, le=10000),
) -> Any:
    if idType and idValue:
        if idType == IdentifierType.PURL:
            try:
                name, version, metadata, wheels, sboms_by_wheel = await resolve_purl(client, cache, idValue)
                pr = build_product_release(name, version, metadata, wheels, sboms_by_wheel)
                return {
                    "timestamp": tea_datetime_serializer(datetime.now(UTC)),
                    "pageStartIndex": pageOffset,
                    "pageSize": pageSize,
                    "totalResults": 1,
                    "results": [tea_dump(pr)],
                }
            except Exception:
                pass

        return {
            "timestamp": tea_datetime_serializer(datetime.now(UTC)),
            "pageStartIndex": pageOffset,
            "pageSize": pageSize,
            "totalResults": 0,
            "results": [],
        }

    entries, total = await cache.list_by_entity_type("product_release", pageOffset, pageSize)
    releases = []
    for entry in entries:
        metadata = await get_version_metadata(client, entry["name"], entry["version"])
        wheels = extract_wheel_urls(metadata)
        entry_sboms: dict[str, list[dict[str, Any]]] = {}
        for wheel in wheels:
            sboms = await _get_sboms_for_wheel(cache, wheel)
            if sboms:
                entry_sboms[wheel.url] = sboms
        pr = build_product_release(entry["name"], entry["version"], metadata, wheels, entry_sboms)
        releases.append(tea_dump(pr))
    return {
        "timestamp": tea_datetime_serializer(datetime.now(UTC)),
        "pageStartIndex": pageOffset,
        "pageSize": pageSize,
        "totalResults": total,
        "results": releases,
    }


async def _resolve_product_release(
    uuid: str, client: httpx.AsyncClient, cache: Cache
) -> tuple[str, str, dict[str, Any], list[WheelInfo], dict[str, list[dict[str, Any]]]] | None:
    lookup = await cache.get_uuid_lookup(uuid)
    if not lookup or lookup["entity_type"] != "product_release":
        return None
    name, version = lookup["name"], lookup["version"]
    metadata = await get_version_metadata(client, name, version)
    wheels = extract_wheel_urls(metadata)
    sboms_by_wheel: dict[str, list[dict[str, Any]]] = {}
    for wheel in wheels:
        sboms = await _get_sboms_for_wheel(cache, wheel)
        if sboms:
            sboms_by_wheel[wheel.url] = sboms
    return name, version, metadata, wheels, sboms_by_wheel


@router.get("/productRelease/{uuid}")
async def get_product_release(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    result = await _resolve_product_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    name, version, metadata, wheels, sboms_by_wheel = result
    pr = build_product_release(name, version, metadata, wheels, sboms_by_wheel)
    return tea_dump(pr)


@router.get("/productRelease/{uuid}/collection/latest")
async def get_product_release_collection_latest(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    result = await _resolve_product_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    name, version, _metadata, wheels, sboms_by_wheel = result
    collection = build_collection_for_product_release(name, version, wheels, sboms_by_wheel)
    return tea_dump(collection)


@router.get("/productRelease/{uuid}/collections")
async def get_product_release_collections(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    result = await _resolve_product_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    name, version, _metadata, wheels, sboms_by_wheel = result
    collection = build_collection_for_product_release(name, version, wheels, sboms_by_wheel)
    return [tea_dump(collection)]


@router.get("/productRelease/{uuid}/collection/{version}")
async def get_product_release_collection_version(
    uuid: str,
    version: int,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    if version != 1:
        return JSONResponse(status_code=404, content=_404)
    result = await _resolve_product_release(uuid, client, cache)
    if not result:
        return JSONResponse(status_code=404, content=_404)
    name, ver, _metadata, wheels, sboms_by_wheel = result
    collection = build_collection_for_product_release(name, ver, wheels, sboms_by_wheel)
    return tea_dump(collection)

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
from pypi_tea.services.mapper import _build_product, resolve_purl

router = APIRouter()

_404 = ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True)


@router.get("/products")
async def list_or_search_products(
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
    idType: str | None = Query(None),
    idValue: str | None = Query(None),
    pageOffset: int = Query(0, ge=0),
    pageSize: int = Query(100, ge=1, le=10000),
) -> Any:
    if idType and idValue:
        if idType == IdentifierType.PURL:
            # Try resolving via PyPI first (versioned PURLs)
            try:
                name, version, _metadata, _wheels, _sboms_by_wheel = await resolve_purl(client, cache, idValue)
                product = _build_product(name, version)
                return {
                    "timestamp": tea_datetime_serializer(datetime.now(UTC)),
                    "pageStartIndex": pageOffset,
                    "pageSize": pageSize,
                    "totalResults": 1,
                    "results": [product.model_dump(by_alias=True)],
                }
            except Exception:
                pass

            # Fallback: search cached products by identifier match
            from pypi_tea.services.mapper import parse_purl

            try:
                purl_name, _ = parse_purl(idValue)
                entries = await cache.find_by_entity_type_and_field("product", "name", purl_name)
                if entries:
                    products = [_build_product(e["name"], None) for e in entries]
                    return {
                        "timestamp": tea_datetime_serializer(datetime.now(UTC)),
                        "pageStartIndex": pageOffset,
                        "pageSize": pageSize,
                        "totalResults": len(products),
                        "results": [p.model_dump(by_alias=True) for p in products],
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

    entries, total = await cache.list_by_entity_type("product", pageOffset, pageSize)
    products = [_build_product(e["name"], None) for e in entries]
    return {
        "timestamp": tea_datetime_serializer(datetime.now(UTC)),
        "pageStartIndex": pageOffset,
        "pageSize": pageSize,
        "totalResults": total,
        "results": [p.model_dump(by_alias=True) for p in products],
    }


@router.get("/product/{uuid}")
async def get_product(
    uuid: str,
    cache: Cache = Depends(get_cache),
) -> Any:
    lookup = await cache.get_uuid_lookup(uuid)
    if not lookup or lookup["entity_type"] != "product":
        return JSONResponse(status_code=404, content=_404)

    name = lookup["name"]
    product = _build_product(name, None)
    return product.model_dump(by_alias=True)


@router.get("/product/{uuid}/releases")
async def get_product_releases(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
    pageOffset: int = Query(0, ge=0),
    pageSize: int = Query(100, ge=1, le=10000),
) -> Any:
    lookup = await cache.get_uuid_lookup(uuid)
    if not lookup or lookup["entity_type"] != "product":
        return JSONResponse(status_code=404, content=_404)

    name = lookup["name"]
    entries = await cache.find_by_entity_type_and_field("product_release", "name", name)
    releases = []
    for entry in entries[pageOffset : pageOffset + pageSize]:
        from pypi_tea.services.mapper import _get_metadata_cached, _get_sboms_for_wheel, build_product_release
        from pypi_tea.services.pypi import extract_wheel_urls

        metadata = await _get_metadata_cached(client, cache, entry["name"], entry["version"])
        wheels = extract_wheel_urls(metadata)
        sboms_by_wheel: dict[str, list[dict[str, Any]]] = {}
        for wheel in wheels:
            sboms = await _get_sboms_for_wheel(cache, wheel)
            if sboms:
                sboms_by_wheel[wheel.url] = sboms
        pr = build_product_release(entry["name"], entry["version"], metadata, wheels, sboms_by_wheel)
        releases.append(tea_dump(pr))
    return {
        "timestamp": tea_datetime_serializer(datetime.now(UTC)),
        "pageStartIndex": pageOffset,
        "pageSize": pageSize,
        "totalResults": len(entries),
        "results": releases,
    }

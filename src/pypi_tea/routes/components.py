from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from libtea.models import ErrorResponse, ErrorType

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.serialization import tea_dump
from pypi_tea.services.mapper import _build_component, _build_release_for_component, _get_metadata_cached
from pypi_tea.services.pypi import WheelInfo, extract_wheel_urls
from pypi_tea.services.uuids import component_release_uuid

router = APIRouter()

_404 = ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True)


async def _resolve_component(uuid: str, cache: Cache) -> WheelInfo | None:
    lookup = await cache.get_uuid_lookup(uuid)
    if not lookup or lookup["entity_type"] != "component":
        return None
    return WheelInfo(
        filename=lookup["filename"],
        url=lookup["url"],
        digests={},
        size=None,
    )


@router.get("/component/{uuid}")
async def get_component(
    uuid: str,
    cache: Cache = Depends(get_cache),
) -> Any:
    wheel = await _resolve_component(uuid, cache)
    if not wheel:
        return JSONResponse(status_code=404, content=_404)
    component = _build_component(wheel)
    return component.model_dump(by_alias=True)


@router.get("/component/{uuid}/releases")
async def get_component_releases(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    wheel = await _resolve_component(uuid, cache)
    if not wheel:
        return JSONResponse(status_code=404, content=_404)

    cr_uuid = component_release_uuid(wheel.url)
    cr_lookup = await cache.get_uuid_lookup(cr_uuid)
    if not cr_lookup:
        return []

    metadata = await _get_metadata_cached(client, cache, cr_lookup["name"], cr_lookup["version"])
    wheels = extract_wheel_urls(metadata)
    matching_wheel = next((w for w in wheels if w.filename == wheel.filename), None)
    if not matching_wheel:
        return []

    upload_time = metadata.get("urls", [{}])[0].get("upload_time_iso_8601")
    created = datetime.fromisoformat(upload_time) if upload_time else datetime.now(UTC)
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)

    release = _build_release_for_component(matching_wheel, cr_lookup["version"], created)
    return [tea_dump(release)]

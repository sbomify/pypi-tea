from typing import Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response
from libtea.models import ErrorResponse, ErrorType

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.services.mapper import _build_artifact, _get_metadata_cached
from pypi_tea.services.pypi import WheelInfo, extract_wheel_urls
from pypi_tea.services.sbom_extractor import extract_sboms

router = APIRouter()

_404 = ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True)


async def _lookup_artifact(uuid: str, cache: Cache) -> dict[str, Any] | None:
    lookup = await cache.get_uuid_lookup(uuid)
    if not lookup or lookup["entity_type"] != "artifact":
        return None
    return lookup


@router.get("/artifact/{uuid}")
async def get_artifact(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    lookup = await _lookup_artifact(uuid, cache)
    if not lookup:
        return JSONResponse(status_code=404, content=_404)

    wheel_url = lookup["wheel_url"]
    sbom_path = lookup["sbom_path"]

    # Rebuild the WheelInfo (we just need the url for the artifact)
    metadata = await _get_metadata_cached(client, cache, lookup["name"], lookup["version"])
    wheels = extract_wheel_urls(metadata)
    matching_wheel = next((w for w in wheels if w.url == wheel_url), None)
    if not matching_wheel:
        matching_wheel = WheelInfo(filename=sbom_path.split("/")[0], url=wheel_url, digests={}, size=None)

    # Try to get the real media_type from cached SBOM content
    media_type = "application/octet-stream"
    cached_sboms = await cache.get_sbom_content(wheel_url)
    if cached_sboms:
        for s in cached_sboms:
            if s["path"] == sbom_path:
                media_type = s.get("media_type", media_type)
                break

    sbom = {"path": sbom_path, "content": "", "media_type": media_type}
    artifact = _build_artifact(matching_wheel, sbom)
    return artifact.model_dump(by_alias=True)


@router.get("/artifact/{uuid}/download")
async def download_artifact(
    uuid: str,
    cache: Cache = Depends(get_cache),
) -> Any:
    lookup = await _lookup_artifact(uuid, cache)
    if not lookup:
        return JSONResponse(status_code=404, content=_404)

    wheel_url = lookup["wheel_url"]
    sbom_path = lookup["sbom_path"]

    # Try cache first
    cached_sboms = await cache.get_sbom_content(wheel_url)
    if cached_sboms:
        for sbom in cached_sboms:
            if sbom["path"] == sbom_path:
                media_type = sbom.get("media_type", "application/octet-stream")
                return Response(content=sbom["content"], media_type=media_type)

    # Cache miss — re-extract from wheel
    sbom_files = await extract_sboms(wheel_url, wheel_size=None)
    for sbom_file in sbom_files:
        if sbom_file.path == sbom_path:
            return Response(content=sbom_file.content, media_type=sbom_file.media_type)

    return JSONResponse(status_code=404, content=_404)

from typing import Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from libtea.models import ErrorResponse, ErrorType

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.services.mapper import _build_artifact
from pypi_tea.services.pypi import WheelInfo, extract_wheel_urls, get_version_metadata
from pypi_tea.services.sbom_extractor import _guess_media_type

router = APIRouter()

_404 = ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True)


@router.get("/artifact/{uuid}")
async def get_artifact(
    uuid: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    lookup = await cache.get_uuid_lookup(uuid)
    if not lookup or lookup["entity_type"] != "artifact":
        return JSONResponse(status_code=404, content=_404)

    wheel_url = lookup["wheel_url"]
    sbom_path = lookup["sbom_path"]

    # Rebuild the WheelInfo (we just need the url for the artifact)
    metadata = await get_version_metadata(client, lookup["name"], lookup["version"])
    wheels = extract_wheel_urls(metadata)
    matching_wheel = next((w for w in wheels if w.url == wheel_url), None)
    if not matching_wheel:
        matching_wheel = WheelInfo(filename=sbom_path.split("/")[0], url=wheel_url, digests={}, size=None)

    sbom = {"path": sbom_path, "content": "", "media_type": _guess_media_type(sbom_path)}
    artifact = _build_artifact(matching_wheel, sbom)
    return artifact.model_dump(by_alias=True)

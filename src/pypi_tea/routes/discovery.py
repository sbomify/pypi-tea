from typing import Any

import httpx
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from libtea.discovery import parse_tei
from libtea.exceptions import TeaDiscoveryError
from libtea.models import ErrorResponse, ErrorType, TeaEndpoint, TeaWellKnown

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.services.mapper import build_discovery_info, resolve_purl

router = APIRouter()


@router.get("/.well-known/tea")
async def well_known_tea() -> Any:
    return TeaWellKnown(
        schemaVersion=1,
        endpoints=(
            TeaEndpoint(
                url=settings.server_root_url,
                versions=(settings.tea_spec_version,),
                priority=1.0,
            ),
        ),
    ).model_dump(by_alias=True)


@router.get("/discovery")
async def discovery(
    tei: str = Query(...),
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    try:
        tei_type, _domain, identifier = parse_tei(tei)
    except TeaDiscoveryError:
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True),
        )

    if tei_type != "purl":
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True),
        )

    try:
        name, version, _metadata, _wheels, _sboms_by_wheel = await resolve_purl(client, cache, identifier)
    except Exception:
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True),
        )

    results = build_discovery_info(name, version)
    return [r.model_dump(by_alias=True) for r in results]

from typing import Any

import httpx
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from libtea.discovery import parse_tei
from libtea.exceptions import TeaDiscoveryError
from libtea.models import ErrorResponse, ErrorType

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.services.mapper import build_discovery_info, resolve_purl

router = APIRouter()


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

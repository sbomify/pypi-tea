from typing import Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from pypi_tea.cache import Cache
from pypi_tea.deps import get_cache, get_http_client
from pypi_tea.services.attestation import AttestationResult, check_wheel_attestation
from pypi_tea.services.mapper import resolve_purl

router = APIRouter()


@router.get("/attestation/{package}/{version}")
async def get_attestation(
    package: str,
    version: str,
    client: httpx.AsyncClient = Depends(get_http_client),
    cache: Cache = Depends(get_cache),
) -> Any:
    purl = f"pkg:pypi/{package}@{version}"
    try:
        name, ver, _metadata, wheels, _sboms_by_wheel = await resolve_purl(client, cache, purl)
    except Exception:
        return JSONResponse(status_code=404, content={"error": "Package or version not found"})

    wheel_results: list[dict[str, Any]] = []
    for wheel in wheels:
        cached = await cache.get_attestation(wheel.url)
        if cached is not None:
            result = AttestationResult.from_dict(cached)
        else:
            result = await check_wheel_attestation(client, cache, name, ver, wheel)
        wheel_results.append({"filename": wheel.filename, "attestation": result.to_dict()})

    return {"package": name, "version": ver, "wheels": wheel_results}

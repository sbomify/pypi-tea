"""TEA API. Every handler answers from the store; unknown releases go through `lookup.ensure_release`."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, Response
from libtea.discovery import parse_tei
from libtea.exceptions import TeaDiscoveryError
from libtea.models import ErrorResponse, ErrorType, IdentifierType, TeaEndpoint, TeaWellKnown
from libtea.server import tea_datetime_serializer

from pypi_tea import store, tea
from pypi_tea.config import settings
from pypi_tea.lookup import ensure_release, read
from pypi_tea.models import Entity, ReleaseRecord, WheelRecord
from pypi_tea.services.pypi import filter_wheels_by_platform
from pypi_tea.usage import usage

router = APIRouter()

MAX_PAGE_SIZE = 100
_404 = ErrorResponse(error=ErrorType.OBJECT_UNKNOWN).model_dump(by_alias=True)


def not_found() -> JSONResponse:
    return JSONResponse(status_code=404, content=_404)


def _page(results: list[dict[str, Any]], offset: int, size: int, total: int) -> dict[str, Any]:
    return {
        "timestamp": tea_datetime_serializer(datetime.now(UTC)),
        "pageStartIndex": offset,
        "pageSize": size,
        "totalResults": total,
        "results": results,
    }


async def _resolve_purl(purl: str) -> tuple[ReleaseRecord, list[WheelRecord]] | None:
    """Versioned PURL -> stored release and the wheels its qualifiers select. None if not on PyPI."""
    try:
        name, version, qualifiers = tea.parse_purl(purl)
    except ValueError:
        return None
    if not version:
        return None
    release = await ensure_release(name, version)
    if release is None:
        return None
    wheels = filter_wheels_by_platform(release.wheels, qualifiers.os_name, qualifiers.arch)
    usage.query(name, version, qualifiers.os_name, qualifiers.arch, any(w.sboms for w in wheels))
    return release, wheels


async def _entity(uuid: str, kind: str) -> Entity | None:
    entity = await read(store.get_entity, uuid)
    return entity if entity is not None and entity.kind == kind else None


async def _release_for(entity: Entity) -> ReleaseRecord | None:
    if entity.version is None:
        return None
    return await read(store.get_release, entity.name, entity.version)


def _wheel(release: ReleaseRecord, url: str | None) -> WheelRecord | None:
    return next((w for w in release.wheels if w.url == url), None)


# --- discovery ---


@router.get("/.well-known/tea")
async def well_known_tea() -> Any:
    return TeaWellKnown(
        schemaVersion=1,
        endpoints=(TeaEndpoint(url=settings.server_root_url, versions=(settings.tea_spec_version,), priority=1.0),),
    ).model_dump(by_alias=True)


@router.get("/discovery")
async def discovery(tei: str = Query(...)) -> Any:
    try:
        tei_type, _domain, identifier = parse_tei(tei)
    except TeaDiscoveryError:
        return not_found()
    if tei_type != "purl":
        return not_found()
    resolved = await _resolve_purl(identifier)
    if resolved is None:
        return not_found()
    release, _ = resolved
    return [d.model_dump(by_alias=True) for d in tea.discovery_info(release.name, release.version)]


# --- products ---


@router.get("/products")
async def list_or_search_products(
    idType: str | None = Query(None),
    idValue: str | None = Query(None),
    pageOffset: int = Query(0, ge=0),
    pageSize: int = Query(100, ge=1, le=10000),
) -> Any:
    size = min(pageSize, MAX_PAGE_SIZE)
    if idType and idValue:
        if idType != IdentifierType.PURL:
            return _page([], pageOffset, size, 0)
        resolved = await _resolve_purl(idValue)
        if resolved is not None:
            return _page([tea.product(resolved[0].name).model_dump(by_alias=True)], pageOffset, size, 1)
        try:
            name, _, _ = tea.parse_purl(idValue)
        except ValueError:
            return _page([], pageOffset, size, 0)
        if await read(store.product_exists, name):
            return _page([tea.product(name).model_dump(by_alias=True)], pageOffset, size, 1)
        return _page([], pageOffset, size, 0)

    names = await read(store.list_products, pageOffset, size)
    total = await read(store.count_products)
    return _page([tea.product(n).model_dump(by_alias=True) for n in names], pageOffset, size, total)


@router.get("/product/{uuid}")
async def get_product(uuid: str) -> Any:
    entity = await _entity(uuid, "product")
    if entity is None:
        return not_found()
    return tea.product(entity.name).model_dump(by_alias=True)


@router.get("/product/{uuid}/releases")
async def get_product_releases(
    uuid: str,
    pageOffset: int = Query(0, ge=0),
    pageSize: int = Query(100, ge=1, le=10000),
) -> Any:
    entity = await _entity(uuid, "product")
    if entity is None:
        return not_found()
    size = min(pageSize, MAX_PAGE_SIZE)
    versions = await read(store.product_release_versions, entity.name)
    results = []
    for version in versions[pageOffset : pageOffset + size]:
        release = await read(store.get_release, entity.name, version)
        if release is not None:
            results.append(tea.dump(tea.product_release(release)))
    return _page(results, pageOffset, size, len(versions))


# --- product releases ---


@router.get("/productReleases")
async def list_or_search_product_releases(
    idType: str | None = Query(None),
    idValue: str | None = Query(None),
    pageOffset: int = Query(0, ge=0),
    pageSize: int = Query(100, ge=1, le=10000),
) -> Any:
    size = min(pageSize, MAX_PAGE_SIZE)
    if idType and idValue:
        if idType != IdentifierType.PURL:
            return _page([], pageOffset, size, 0)
        resolved = await _resolve_purl(idValue)
        if resolved is None:
            return _page([], pageOffset, size, 0)
        release, wheels = resolved
        return _page([tea.dump(tea.product_release(release, wheels))], pageOffset, size, 1)

    keys = await read(store.list_release_keys, pageOffset, size)
    total = await read(store.count_listed_releases)
    results = []
    for name, version in keys:
        stored = await read(store.get_release, name, version)
        if stored is not None:
            results.append(tea.dump(tea.product_release(stored)))
    return _page(results, pageOffset, size, total)


async def _product_release(uuid: str) -> ReleaseRecord | None:
    entity = await _entity(uuid, "product_release")
    return None if entity is None else await _release_for(entity)


@router.get("/productRelease/{uuid}")
async def get_product_release(uuid: str) -> Any:
    release = await _product_release(uuid)
    return not_found() if release is None else tea.dump(tea.product_release(release))


@router.get("/productRelease/{uuid}/collection/latest")
async def get_product_release_collection_latest(uuid: str) -> Any:
    release = await _product_release(uuid)
    return not_found() if release is None else tea.dump(tea.product_collection(release))


@router.get("/productRelease/{uuid}/collections")
async def get_product_release_collections(uuid: str) -> Any:
    release = await _product_release(uuid)
    return not_found() if release is None else [tea.dump(tea.product_collection(release))]


@router.get("/productRelease/{uuid}/collection/{version}")
async def get_product_release_collection_version(uuid: str, version: int) -> Any:
    release = await _product_release(uuid) if version == 1 else None
    return not_found() if release is None else tea.dump(tea.product_collection(release))


# --- components ---


async def _component(uuid: str, kind: str) -> tuple[ReleaseRecord, WheelRecord] | None:
    entity = await _entity(uuid, kind)
    if entity is None:
        return None
    release = await _release_for(entity)
    if release is None:
        return None
    wheel = _wheel(release, entity.wheel_url)
    return None if wheel is None else (release, wheel)


@router.get("/component/{uuid}")
async def get_component(uuid: str) -> Any:
    found = await _component(uuid, "component")
    return not_found() if found is None else tea.component(found[1]).model_dump(by_alias=True)


@router.get("/component/{uuid}/releases")
async def get_component_releases(uuid: str) -> Any:
    found = await _component(uuid, "component")
    return not_found() if found is None else [tea.dump(tea.component_release(*found))]


@router.get("/componentRelease/{uuid}")
async def get_component_release(uuid: str) -> Any:
    found = await _component(uuid, "component_release")
    return not_found() if found is None else tea.dump(tea.component_release_with_collection(*found))


@router.get("/componentRelease/{uuid}/collection/latest")
async def get_component_release_collection_latest(uuid: str) -> Any:
    found = await _component(uuid, "component_release")
    return not_found() if found is None else tea.dump(tea.component_collection(*found))


@router.get("/componentRelease/{uuid}/collections")
async def get_component_release_collections(uuid: str) -> Any:
    found = await _component(uuid, "component_release")
    return not_found() if found is None else [tea.dump(tea.component_collection(*found))]


@router.get("/componentRelease/{uuid}/collection/{coll_version}")
async def get_component_release_collection_version(uuid: str, coll_version: int) -> Any:
    found = await _component(uuid, "component_release") if coll_version == 1 else None
    return not_found() if found is None else tea.dump(tea.component_collection(*found))


# --- artifacts ---


@router.get("/artifact/{uuid}/latest")
@router.get("/artifact/{uuid}")
async def get_artifact(uuid: str) -> Any:
    found = await _component(uuid, "artifact")
    if found is None:
        return not_found()
    _, wheel = found
    sbom = next((s for s in wheel.sboms if s.uuid == uuid), None)
    return not_found() if sbom is None else tea.artifact(wheel, sbom).model_dump(by_alias=True)


@router.get("/artifact/{uuid}/download")
async def download_artifact(uuid: str) -> Any:
    found = await read(store.get_sbom_content, uuid)
    if found is None:
        return not_found()
    content, media_type = found
    return Response(content=content, media_type=media_type)


# --- attestation (non-TEA) ---


@router.get("/attestation/{package}/{version}")
async def get_attestation(package: str, version: str) -> Any:
    resolved = await _resolve_purl(f"pkg:pypi/{package}@{version}")
    if resolved is None:
        return JSONResponse(status_code=404, content={"error": "Package or version not found"})
    release, wheels = resolved
    return {
        "package": release.name,
        "version": release.version,
        "wheels": [
            {"filename": w.filename, "attestation": w.attestation or {"status": "not_available"}} for w in wheels
        ],
    }

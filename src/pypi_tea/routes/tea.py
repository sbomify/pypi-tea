"""TEA API. Every handler answers from the store; unknown releases go through `lookup.ensure_release`.

`router(legacy)` builds the API for one spec version: TEA 1.0.0, or 0.4.0 for clients that still speak it.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, Response
from libtea.discovery import parse_tei, purl_from_tei
from libtea.exceptions import TeaDiscoveryError
from libtea.models import ErrorResponse, ErrorType, IdentifierType, TeaEndpoint, TeaWellKnown
from libtea.server import tea_datetime_serializer, to_wire

from pypi_tea import analytics, store, tea
from pypi_tea.config import settings
from pypi_tea.lookup import Overloaded, Pending, ensure_release, read
from pypi_tea.models import Entity, ReleaseRecord, WheelRecord
from pypi_tea.services.pypi import filter_wheels_by_platform
from pypi_tea.usage import usage

MAX_PAGE_SIZE = 100
_404 = to_wire(ErrorResponse(error=ErrorType.OBJECT_UNKNOWN))


class InvalidRequest(Exception):
    """A TEA 1.0.0 request the server rejects with 400 and a TEA error body."""

    def __init__(self, message: str, error: ErrorType = ErrorType.INVALID_REQUEST) -> None:
        super().__init__(message)
        self.error = error

    def response(self) -> JSONResponse:
        return JSONResponse(status_code=400, content=to_wire(ErrorResponse(error=self.error, message=str(self))))


def not_found() -> JSONResponse:
    return JSONResponse(status_code=404, content=_404)


def _paging(
    pageToken: str | None = Query(None),
    pageSize: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
) -> tuple[int, int]:
    """TEA 1.0.0 paging: `(offset, size)`. The page token is the offset of the next page."""
    if pageToken is None:
        return 0, pageSize
    if not (pageToken.isascii() and pageToken.isdigit()):
        raise InvalidRequest(f"Invalid pageToken: {pageToken!r}", ErrorType.INVALID_PAGE_TOKEN)
    return int(pageToken), pageSize


def _legacy_paging(
    pageOffset: int = Query(0, ge=0),
    pageSize: int = Query(100, ge=1, le=10000),
) -> tuple[int, int]:
    """TEA 0.4.0 paging: `(offset, size)`, the size capped at `MAX_PAGE_SIZE`."""
    return pageOffset, min(pageSize, MAX_PAGE_SIZE)


async def _resolve_purl(purl: str, source: str) -> tuple[ReleaseRecord, list[WheelRecord]] | None:
    """Versioned PURL -> stored release and the wheels its qualifiers select. None if not on PyPI.

    `source` names the endpoint asking, for analytics.
    """
    try:
        name, version, qualifiers = tea.parse_purl(purl)
    except ValueError:
        analytics.capture("sbom_lookup_failed", {"source": source, "reason": "invalid_purl"})
        return None
    failed = {"source": source, "package": name, "version": version or None}
    if not version:
        analytics.capture("sbom_lookup_failed", failed | {"reason": "unversioned"})
        return None
    try:
        release = await ensure_release(name, version)
    except Overloaded:
        analytics.capture("sbom_lookup_failed", failed | {"reason": "overloaded"})
        raise
    except Pending:
        analytics.capture("sbom_lookup_failed", failed | {"reason": "pending"})
        raise
    if release is None:
        analytics.capture("sbom_lookup_failed", failed | {"reason": "not_on_pypi"})
        return None
    wheels = filter_wheels_by_platform(release.wheels, qualifiers.os_name, qualifiers.arch)
    has_sbom = any(w.sboms for w in wheels)
    usage.query(name, version, qualifiers.os_name, qualifiers.arch, has_sbom)
    sboms = [s for w in wheels for s in w.sboms]
    analytics.capture(
        "sbom_lookup",
        {
            "source": source,
            "package": name,
            "version": version,
            "os": qualifiers.os_name,
            "arch": qualifiers.arch,
            "platform_qualified": bool(qualifiers.os_name or qualifiers.arch),
            "has_sbom": has_sbom,
            "wheel_count": len(wheels),
            "sbom_count": len(sboms),
            "sbom_formats": sorted({s.family for s in sboms}),
            "has_invalid_sbom": any(not s.valid for s in sboms),
            "attested": any((w.attestation or {}).get("status") == "verified" for w in wheels),
        },
    )
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


async def _product_release(uuid: str) -> ReleaseRecord | None:
    entity = await _entity(uuid, "product_release")
    return None if entity is None else await _release_for(entity)


async def _component(uuid: str, kind: str) -> tuple[ReleaseRecord, WheelRecord] | None:
    entity = await _entity(uuid, kind)
    if entity is None:
        return None
    release = await _release_for(entity)
    if release is None:
        return None
    wheel = _wheel(release, entity.wheel_url)
    return None if wheel is None else (release, wheel)


def _media_type_key(media_type: str) -> tuple[str, frozenset[tuple[str, str]]]:
    """Type and subtype compare case-insensitively, parameter names too; parameter values exactly."""
    essence, *params = media_type.split(";")
    pairs = (p.partition("=") for p in params if p.strip())
    return essence.strip().lower(), frozenset((k.strip().lower(), v.strip().strip('"')) for k, _, v in pairs)


async def _download(uuid: str, media_type: str | None = None) -> Response:
    found = await read(store.get_sbom_content, uuid)
    if found is None:
        return not_found()
    content, stored_type = found
    if media_type is not None and _media_type_key(media_type) != _media_type_key(stored_type):
        return JSONResponse(
            status_code=406, content=to_wire(ErrorResponse(error=ErrorType.NO_ACCEPTABLE_FORMAT, message=stored_type))
        )
    if analytics.enabled():
        entity = await read(store.get_entity, uuid)
        analytics.capture(
            "sbom_downloaded",
            {
                "artifact_uuid": uuid,
                "package": entity.name if entity else None,
                "version": entity.version if entity else None,
                "media_type": stored_type,
                "size_bytes": len(content),
            },
        )
    return Response(content=content, media_type=stored_type)


# Not a TEA endpoint: the package pages' download link, kept at the root next to the 1.0.0 API.
downloads = APIRouter()


@downloads.get("/artifact/{uuid}/download")
async def download_artifact(uuid: str) -> Response:
    return await _download(uuid)


# Everything outside the versioned TEA API: discovery of the API itself and the attestation lookup.
common = APIRouter()


@common.get("/.well-known/tea")
async def well_known_tea() -> Any:
    return to_wire(
        TeaWellKnown(
            schemaVersion=1,
            endpoints=(TeaEndpoint(url=settings.server_root_url, versions=tea.TEA_VERSIONS, priority=1.0),),
        )
    )


@common.get("/attestation/{package}/{version}")
async def get_attestation(package: str, version: str) -> Any:
    resolved = await _resolve_purl(f"pkg:pypi/{package}@{version}", "attestation")
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


def router(legacy: bool) -> APIRouter:
    """The TEA API: 1.0.0, or 0.4.0 with `legacy=True`."""
    api = APIRouter()
    paging: Callable[..., tuple[int, int]] = _legacy_paging if legacy else _paging

    def wire(model: Any) -> Any:
        return to_wire(model, legacy=legacy)

    def page(results: list[Any], offset: int, size: int, total: int) -> dict[str, Any]:
        """One page of already-serialized results, out of `total` starting at `offset`."""
        if legacy:
            return {
                "timestamp": tea_datetime_serializer(datetime.now(UTC)),
                "pageStartIndex": offset,
                "pageSize": size,
                "totalResults": total,
                "results": results,
            }
        if offset + size < total:
            return {"hasNext": True, "nextPageToken": str(offset + size), "results": results}
        return {"hasNext": False, "results": results}

    def single(result: Any, offset: int, size: int) -> dict[str, Any]:
        """A one-item list: the 1.0.0 endpoints that page what can only ever be one result."""
        return page([result] if offset == 0 else [], offset, size, 1)

    # --- discovery ---

    @api.get("/discovery")
    async def discovery(tei: str | None = Query(None), purl: str | None = Query(None)) -> Any:
        if legacy:
            if tei is None or purl is not None:
                return not_found()
        elif (tei is None) == (purl is None):
            raise InvalidRequest("Provide exactly one of tei and purl")
        if tei is not None:
            try:
                tei_type, _domain, _identifier = parse_tei(tei)
            except TeaDiscoveryError as exc:
                if legacy:
                    return not_found()
                raise InvalidRequest(str(exc)) from exc
            if tei_type != "purl":
                analytics.capture(
                    "sbom_lookup_failed", {"source": "discovery", "reason": "unsupported_tei", "tei_type": tei_type}
                )
                return not_found()
            try:
                purl = purl_from_tei(tei)
            except TeaDiscoveryError as exc:
                if legacy:
                    return not_found()
                raise InvalidRequest(str(exc)) from exc
        assert purl is not None
        resolved = await _resolve_purl(purl, "discovery")
        if resolved is None:
            return not_found()
        release, _ = resolved
        return wire(tea.discovery_info(release.name, release.version))

    # --- products ---

    @api.get("/products")
    async def list_or_search_products(
        idType: str | None = Query(None),
        idValue: str | None = Query(None),
        paged: tuple[int, int] = Depends(paging),
    ) -> Any:
        offset, size = paged
        if idType and idValue:
            if idType != IdentifierType.PURL:
                return page([], offset, size, 0)
            resolved = await _resolve_purl(idValue, "products")
            if resolved is not None:
                return single(wire(tea.product(resolved[0].name)), offset, size)
            try:
                name, _, _ = tea.parse_purl(idValue)
            except ValueError:
                return page([], offset, size, 0)
            if await read(store.product_exists, name):
                return single(wire(tea.product(name)), offset, size)
            return page([], offset, size, 0)

        names = await read(store.list_products, offset, size)
        total = await read(store.count_products)
        return page([wire(tea.product(n)) for n in names], offset, size, total)

    @api.get("/product/{uuid}")
    async def get_product(uuid: str) -> Any:
        entity = await _entity(uuid, "product")
        return not_found() if entity is None else wire(tea.product(entity.name))

    @api.get("/product/{uuid}/releases")
    async def get_product_releases(uuid: str, paged: tuple[int, int] = Depends(paging)) -> Any:
        offset, size = paged
        entity = await _entity(uuid, "product")
        if entity is None:
            return not_found()
        versions = await read(store.product_release_versions, entity.name)
        results = []
        for version in versions[offset : offset + size]:
            release = await read(store.get_release, entity.name, version)
            if release is not None:
                results.append(wire(tea.product_release(release)))
        return page(results, offset, size, len(versions))

    # --- product releases ---

    @api.get("/productReleases")
    async def list_or_search_product_releases(
        idType: str | None = Query(None),
        idValue: str | None = Query(None),
        paged: tuple[int, int] = Depends(paging),
    ) -> Any:
        offset, size = paged
        if idType and idValue:
            if idType != IdentifierType.PURL:
                return page([], offset, size, 0)
            resolved = await _resolve_purl(idValue, "productReleases")
            if resolved is None:
                return page([], offset, size, 0)
            release, wheels = resolved
            return single(wire(tea.product_release(release, wheels)), offset, size)

        keys = await read(store.list_release_keys, offset, size)
        total = await read(store.count_listed_releases)
        results = []
        for name, version in keys:
            stored = await read(store.get_release, name, version)
            if stored is not None:
                results.append(wire(tea.product_release(stored)))
        return page(results, offset, size, total)

    @api.get("/productRelease/{uuid}")
    async def get_product_release(uuid: str) -> Any:
        release = await _product_release(uuid)
        if release is None:
            return not_found()
        return wire(tea.product_release(release) if legacy else tea.product_release_with_collection(release))

    @api.get("/productRelease/{uuid}/collection/latest")
    async def get_product_release_collection_latest(uuid: str) -> Any:
        release = await _product_release(uuid)
        return not_found() if release is None else wire(tea.product_collection(release, legacy))

    if legacy:

        @api.get("/productRelease/{uuid}/collections")
        async def get_product_release_collections(uuid: str) -> Any:
            release = await _product_release(uuid)
            return not_found() if release is None else [wire(tea.product_collection(release, legacy))]

    else:

        @api.get("/productRelease/{uuid}/collections")
        async def get_product_release_collections_page(uuid: str, paged: tuple[int, int] = Depends(paging)) -> Any:
            release = await _product_release(uuid)
            return not_found() if release is None else single(wire(tea.product_collection(release)), *paged)

    @api.get("/productRelease/{uuid}/collection/{version}")
    async def get_product_release_collection_version(uuid: str, version: int) -> Any:
        release = await _product_release(uuid) if version == 1 else None
        return not_found() if release is None else wire(tea.product_collection(release, legacy))

    # --- components ---

    @api.get("/component/{uuid}")
    async def get_component(uuid: str) -> Any:
        found = await _component(uuid, "component")
        return not_found() if found is None else wire(tea.component(found[1]))

    if legacy:

        @api.get("/component/{uuid}/releases")
        async def get_component_releases(uuid: str) -> Any:
            found = await _component(uuid, "component")
            return not_found() if found is None else [wire(tea.component_release(*found))]

    else:

        @api.get("/component/{uuid}/releases")
        async def get_component_releases_page(uuid: str, paged: tuple[int, int] = Depends(paging)) -> Any:
            found = await _component(uuid, "component")
            return not_found() if found is None else single(wire(tea.component_release(*found)), *paged)

    @api.get("/componentRelease/{uuid}")
    async def get_component_release(uuid: str) -> Any:
        found = await _component(uuid, "component_release")
        return not_found() if found is None else wire(tea.component_release_with_collection(*found, legacy))

    @api.get("/componentRelease/{uuid}/collection/latest")
    async def get_component_release_collection_latest(uuid: str) -> Any:
        found = await _component(uuid, "component_release")
        return not_found() if found is None else wire(tea.component_collection(*found, legacy))

    if legacy:

        @api.get("/componentRelease/{uuid}/collections")
        async def get_component_release_collections(uuid: str) -> Any:
            found = await _component(uuid, "component_release")
            return not_found() if found is None else [wire(tea.component_collection(*found, legacy))]

    else:

        @api.get("/componentRelease/{uuid}/collections")
        async def get_component_release_collections_page(uuid: str, paged: tuple[int, int] = Depends(paging)) -> Any:
            found = await _component(uuid, "component_release")
            return not_found() if found is None else single(wire(tea.component_collection(*found)), *paged)

    @api.get("/componentRelease/{uuid}/collection/{coll_version}")
    async def get_component_release_collection_version(uuid: str, coll_version: int) -> Any:
        found = await _component(uuid, "component_release") if coll_version == 1 else None
        return not_found() if found is None else wire(tea.component_collection(*found, legacy))

    # --- artifacts ---

    async def get_artifact(uuid: str) -> Any:
        found = await _component(uuid, "artifact")
        if found is None:
            return not_found()
        release, wheel = found
        sbom = next((s for s in wheel.sboms if s.uuid == uuid), None)
        return not_found() if sbom is None else wire(tea.artifact(release, sbom, legacy))

    if legacy:
        api.get("/artifact/{uuid}")(get_artifact)
        api.get("/artifact/{uuid}/latest")(get_artifact)
        api.get("/artifact/{uuid}/download")(download_artifact)
        return api

    # Artifacts never change: version 1 is the only one, and "latest".
    @api.get("/artifact/{uuid}/latest")
    async def get_artifact_latest(uuid: str) -> Any:
        return await get_artifact(uuid)

    @api.get("/artifact/{uuid}/latest/download")
    async def download_artifact_latest(uuid: str, mediaType: str | None = Query(None)) -> Response:
        return await _download(uuid, mediaType)

    @api.get("/artifact/{uuid}/{artifact_version}")
    async def get_artifact_version(uuid: str, artifact_version: int) -> Any:
        return await get_artifact(uuid) if artifact_version == 1 else not_found()

    @api.get("/artifact/{uuid}/{artifact_version}/download")
    async def download_artifact_version(
        uuid: str, artifact_version: int, mediaType: str | None = Query(None)
    ) -> Response:
        return await _download(uuid, mediaType) if artifact_version == 1 else not_found()

    return api

"""TEA 1.0.0 API. Every handler answers from the store; unknown releases go through `lookup.ensure_release`."""

import base64
import json
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response
from libtea.discovery import parse_tei, purl_from_tei
from libtea.exceptions import TeaDiscoveryError
from libtea.models import (
    ErrorResponse,
    ErrorType,
    IdentifierType,
    PaginatedCollectionResponse,
    PaginatedComponentReleaseResponse,
    PaginatedComponentResponse,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    TeaEndpoint,
    TeaWellKnown,
)
from libtea.server import to_wire

from pypi_tea import analytics, store, tea
from pypi_tea.config import TEA_VERSION, settings
from pypi_tea.lookup import Overloaded, Pending, ensure_release, read
from pypi_tea.models import Entity, ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.services.pypi import filter_wheels_by_platform
from pypi_tea.services.uuids import component_release_uuid, product_release_uuid
from pypi_tea.usage import usage

router = APIRouter()

IdType = Literal["CPE", "TEI", "PURL", "COMPLIANCE_DOCUMENT"]
SortOrder = Literal["asc", "desc"]
ReleaseSortField = Literal["createdDate", "releaseDate", "version"]
PAGE_SIZE = Query(25, ge=1, le=100, description="The maximum number of results to return")
PAGE_TOKEN = Query(None, max_length=4096, description="nextPageToken of the previous page")
SORT_ORDER = Query("asc", description="The direction of the sort")


def _error(status: int, error: ErrorType, message: str | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content=to_wire(ErrorResponse(error=error, message=message)))


def not_found(error: ErrorType = ErrorType.OBJECT_UNKNOWN) -> JSONResponse:
    return _error(404, error)


def invalid(message: str, error: ErrorType = ErrorType.INVALID_REQUEST) -> JSONResponse:
    return _error(400, error, message)


# --- pagination ---
#
# A pageToken is the cursor where the next page starts plus the query that produced it: the path and
# every parameter that selects or orders results. A token sent with any other query is rejected.
# Tokens are not signed: everything served is public, so a forged cursor only selects another page of
# it, and SQL takes cursors as parameters. Sign them if any list ever needs access control.


class BadPageToken(Exception):
    """A pageToken this server did not issue for this query. Answered 400 INVALID_PAGE_TOKEN."""


def _state(request: Request, *params: str | None) -> list[str | None]:
    return [request.url.path, *params]


def _cursor(token: str | None, state: list[str | None], types: tuple[type, ...]) -> tuple[Any, ...] | None:
    """The cursor a pageToken carries, typed as `types`, or None on the first page."""
    if token is None:
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        query, cursor = data["q"], tuple(data["c"])
    except (ValueError, TypeError, KeyError) as exc:
        raise BadPageToken("pageToken is not valid") from exc
    if query != state:
        raise BadPageToken("pageToken belongs to a different query")
    if len(cursor) != len(types) or any(
        type(v) is not t or (isinstance(v, int) and v < 0) for v, t in zip(cursor, types, strict=True)
    ):
        raise BadPageToken("pageToken is not valid")
    return cursor


def _page(model: Any, results: Sequence[Any], state: list[str | None], next_cursor: Sequence[Any] | None) -> Any:
    if next_cursor is None:
        return to_wire(model(has_next=False, results=tuple(results)))
    token = json.dumps({"q": state, "c": list(next_cursor)}, separators=(",", ":"))
    next_page_token = base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")
    return to_wire(model(has_next=True, next_page_token=next_page_token, results=tuple(results)))


def _window[T](items: Sequence[T], size: int, token: str | None, state: list[str | None]) -> tuple[Sequence[T], Any]:
    """One page of a list held in memory, and the cursor of the next (None on the last)."""
    (offset,) = _cursor(token, state, (int,)) or (0,)
    end = offset + size
    return items[offset:end], ((end,) if end < len(items) else None)


# --- sorting (TEA 1.0.0: by the sort field, then by uuid, both in the sort order) ---


def _release_key(field: str, uuid: str, version: str, first_seen: int | None, uploaded: datetime | None) -> Any:
    if field == "version":
        return (version, uuid)  # Python string order, i.e. by code point
    if field == "releaseDate":
        # A release without a date sorts after the dated ones ascending, and before them descending.
        return (uploaded is None, uploaded or datetime.min.replace(tzinfo=UTC), uuid)
    return (first_seen or 0, uuid)


def _sort_wheels(wheels: list[WheelRecord], desc: bool) -> list[WheelRecord]:
    """A release's component releases share every sort field, so uuid alone orders them."""
    return sorted(wheels, key=lambda w: component_release_uuid(w.url), reverse=desc)


# --- lookups ---


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
    if qualifiers.file_name:
        wheels = [w for w in wheels if w.filename == qualifiers.file_name]
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


async def _search(
    id_type: str | None, id_value: str | None, source: str
) -> tuple[ReleaseRecord, list[WheelRecord]] | None:
    """The release a PURL search names. Every other identifier type matches nothing here."""
    if id_type != IdentifierType.PURL or not id_value:
        return None
    return await _resolve_purl(id_value, source)


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
    return to_wire(
        TeaWellKnown(
            schema_version=1,
            endpoints=(TeaEndpoint(url=settings.server_root_url, versions=(TEA_VERSION,), priority=1.0),),
        )
    )


@router.get("/discovery")
async def discovery(
    tei: str | None = Query(None, max_length=2048, description="TEI, as tei://<domain>/<type>/<id> or urn:tei:"),
    purl: str | None = Query(None, max_length=2048, description="PURL of a PyPI release"),
) -> Any:
    if (tei is None) == (purl is None):
        return invalid("Give exactly one of tei and purl")
    if tei is not None:
        try:
            tei_type = parse_tei(tei)[0]
            purl = purl_from_tei(tei) if tei_type == "purl" else None
        except TeaDiscoveryError:
            return invalid("Not a valid TEI")
    if purl is None:  # a TEI of a type other than purl
        analytics.capture(
            "sbom_lookup_failed", {"source": "discovery", "reason": "unsupported_tei", "tei_type": tei_type}
        )
        return not_found()
    resolved = await _resolve_purl(purl, "discovery")
    if resolved is None:
        return not_found()
    release, _ = resolved
    return to_wire(tea.discovery_info(release.name, release.version))


# --- products ---


@router.get("/products")
async def query_products(
    request: Request,
    idType: IdType | None = Query(None),
    idValue: str | None = Query(None, max_length=2048),
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: Literal["name"] = Query("name"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    state = _state(request, idType, idValue, sortField, sortOrder)
    if idType and idValue:
        names: list[str] = []
        if (resolved := await _search(idType, idValue, "products")) is not None:
            names = [resolved[0].name]
        elif idType == IdentifierType.PURL:
            try:
                name, _, _ = tea.parse_purl(idValue)
            except ValueError:
                pass
            else:
                if await read(store.product_exists, name):
                    names = [name]
        window, next_cursor = _window(names, pageSize, pageToken, state)
        return _page(PaginatedProductResponse, [tea.product(n) for n in window], state, next_cursor)

    after = _cursor(pageToken, state, (str,))
    names = await read(store.product_names_page, after, pageSize + 1, sortOrder == "desc")
    more = len(names) > pageSize
    names = names[:pageSize]
    return _page(PaginatedProductResponse, [tea.product(n) for n in names], state, (names[-1],) if more else None)


@router.get("/product/{uuid}")
async def get_product(uuid: str) -> Any:
    entity = await _entity(uuid, "product")
    if entity is None:
        return not_found()
    return to_wire(tea.product(entity.name))


@router.get("/product/{uuid}/releases")
async def list_product_releases(
    request: Request,
    uuid: str,
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: ReleaseSortField = Query("createdDate"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    entity = await _entity(uuid, "product")
    if entity is None:
        return not_found()
    name = entity.name
    rows = await read(store.product_release_dates, name)
    rows.sort(
        key=lambda r: _release_key(sortField, product_release_uuid(name, r[0]), r[0], r[1], tea.release_date(r[2])),
        reverse=sortOrder == "desc",
    )
    state = _state(request, sortField, sortOrder)
    window, next_cursor = _window([version for version, _, _ in rows], pageSize, pageToken, state)
    results = []
    for version in window:
        release = await read(store.get_release, name, version)
        if release is not None:
            results.append(tea.product_release(release))
    return _page(PaginatedProductReleaseResponse, results, state, next_cursor)


# --- product releases ---


def _catalog_sort(sortField: str) -> JSONResponse | None:
    if sortField == "createdDate":
        return None
    # The catalog is only kept in createdDate order; sorting it another way would need an index per field.
    return invalid(f"sortField={sortField} is supported within one product or one search, not across the catalog")


@router.get("/productReleases")
async def query_product_releases(
    request: Request,
    idType: IdType | None = Query(None),
    idValue: str | None = Query(None, max_length=2048),
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: ReleaseSortField = Query("createdDate"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    state = _state(request, idType, idValue, sortField, sortOrder)
    if idType and idValue:
        resolved = await _search(idType, idValue, "productReleases")
        found = [] if resolved is None else [tea.product_release(*resolved)]
        window, next_cursor = _window(found, pageSize, pageToken, state)
        return _page(PaginatedProductReleaseResponse, window, state, next_cursor)

    if (refused := _catalog_sort(sortField)) is not None:
        return refused
    after = _cursor(pageToken, state, (int,))
    keys = await read(store.release_keys_page, after, pageSize + 1, sortOrder == "desc")
    results = []
    for _, name, version in keys[:pageSize]:
        stored = await read(store.get_release, name, version)
        if stored is not None:
            results.append(tea.product_release(stored))
    more = len(keys) > pageSize
    return _page(PaginatedProductReleaseResponse, results, state, (keys[pageSize - 1][0],) if more else None)


async def _product_release(uuid: str) -> ReleaseRecord | None:
    entity = await _entity(uuid, "product_release")
    return None if entity is None else await _release_for(entity)


@router.get("/productRelease/{uuid}")
async def get_product_release(uuid: str) -> Any:
    release = await _product_release(uuid)
    return not_found() if release is None else to_wire(tea.product_release(release, with_collection=True))


@router.get("/productRelease/{uuid}/collection/latest")
async def get_latest_product_release_collection(uuid: str) -> Any:
    release = await _product_release(uuid)
    return not_found() if release is None else to_wire(tea.product_collection(release))


@router.get("/productRelease/{uuid}/collections")
async def list_product_release_collections(
    request: Request,
    uuid: str,
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: Literal["version"] = Query("version"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    release = await _product_release(uuid)
    if release is None:
        return not_found()
    state = _state(request, sortField, sortOrder)
    window, next_cursor = _window([tea.product_collection(release)], pageSize, pageToken, state)
    return _page(PaginatedCollectionResponse, window, state, next_cursor)


@router.get("/productRelease/{uuid}/collection/{collectionVersion}")
async def get_product_release_collection_by_version(uuid: str, collectionVersion: int) -> Any:
    release = await _product_release(uuid) if collectionVersion == 1 else None
    return not_found() if release is None else to_wire(tea.product_collection(release))


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


@router.get("/components")
async def query_components(
    request: Request,
    idType: IdType | None = Query(None),
    idValue: str | None = Query(None, max_length=2048),
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: Literal["name"] = Query("name"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    state = _state(request, idType, idValue, sortField, sortOrder)
    desc = sortOrder == "desc"
    if idType and idValue:
        resolved = await _search(idType, idValue, "components")
        found = (
            []
            if resolved is None
            else [tea.component(resolved[0].name, resolved[0].version, w.filename) for w in resolved[1]]
        )
        found.sort(key=lambda c: (c.name, c.uuid), reverse=desc)
        window, next_cursor = _window(found, pageSize, pageToken, state)
        return _page(PaginatedComponentResponse, window, state, next_cursor)

    after = _cursor(pageToken, state, (str, str))
    rows = await read(store.wheels_page, after, pageSize + 1, desc)
    more = len(rows) > pageSize
    rows = rows[:pageSize]
    results = [tea.component(name, version, filename) for filename, _, name, version in rows]
    return _page(PaginatedComponentResponse, results, state, rows[-1][:2] if more else None)


@router.get("/component/{uuid}")
async def get_component(uuid: str) -> Any:
    found = await _component(uuid, "component")
    if found is None:
        return not_found()
    release, wheel = found
    return to_wire(tea.component(release.name, release.version, wheel.filename))


@router.get("/component/{uuid}/releases")
async def list_component_releases(
    request: Request,
    uuid: str,
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: ReleaseSortField = Query("createdDate"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    # A component is one wheel file, so it has exactly one release.
    found = await _component(uuid, "component")
    if found is None:
        return not_found()
    state = _state(request, sortField, sortOrder)
    window, next_cursor = _window([tea.component_release(*found)], pageSize, pageToken, state)
    return _page(PaginatedComponentReleaseResponse, window, state, next_cursor)


# --- component releases ---


@router.get("/componentReleases")
async def query_component_releases(
    request: Request,
    idType: IdType | None = Query(None),
    idValue: str | None = Query(None, max_length=2048),
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: ReleaseSortField = Query("createdDate"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    state = _state(request, idType, idValue, sortField, sortOrder)
    desc = sortOrder == "desc"
    if idType and idValue:
        resolved = await _search(idType, idValue, "componentReleases")
        found = (
            [] if resolved is None else [tea.component_release(resolved[0], w) for w in _sort_wheels(resolved[1], desc)]
        )
        window, next_cursor = _window(found, pageSize, pageToken, state)
        return _page(PaginatedComponentReleaseResponse, window, state, next_cursor)

    if (refused := _catalog_sort(sortField)) is not None:
        return refused
    # Releases in createdDate order, each expanded into its wheels. The cursor is the position of the
    # release to resume in and how many of its wheels were already sent. Pages can come up short.
    cursor = _cursor(pageToken, state, (int, int))
    resume_pos, skip = cursor if cursor is not None else (None, 0)
    after = None if resume_pos is None else (resume_pos + (1 if desc else -1),)
    keys = await read(store.release_keys_page, after, pageSize + 1, desc)
    results: list[Any] = []
    resume: tuple[int, int] | None = None
    for pos, name, version in keys:
        release = await read(store.get_release, name, version)
        pairs = [] if release is None else [(release, w) for w in _sort_wheels(release.wheels, desc)]
        for i in range(skip if pos == resume_pos else 0, len(pairs)):
            if len(results) == pageSize:
                resume = (pos, i)
                break
            results.append(tea.component_release(*pairs[i]))
        if resume is not None:
            break
    else:
        if len(keys) > pageSize:
            resume = (keys[-1][0], len(pairs))
    return _page(PaginatedComponentReleaseResponse, results, state, resume)


@router.get("/componentRelease/{uuid}")
async def get_component_release(uuid: str) -> Any:
    found = await _component(uuid, "component_release")
    return not_found() if found is None else to_wire(tea.component_release_with_collection(*found))


@router.get("/componentRelease/{uuid}/collection/latest")
async def get_latest_component_release_collection(uuid: str) -> Any:
    found = await _component(uuid, "component_release")
    return not_found() if found is None else to_wire(tea.component_collection(*found))


@router.get("/componentRelease/{uuid}/collections")
async def list_component_release_collections(
    request: Request,
    uuid: str,
    pageSize: int = PAGE_SIZE,
    pageToken: str | None = PAGE_TOKEN,
    sortField: Literal["version"] = Query("version"),
    sortOrder: SortOrder = SORT_ORDER,
) -> Any:
    found = await _component(uuid, "component_release")
    if found is None:
        return not_found()
    state = _state(request, sortField, sortOrder)
    window, next_cursor = _window([tea.component_collection(*found)], pageSize, pageToken, state)
    return _page(PaginatedCollectionResponse, window, state, next_cursor)


@router.get("/componentRelease/{uuid}/collection/{collectionVersion}")
async def get_component_release_collection_by_version(uuid: str, collectionVersion: int) -> Any:
    found = await _component(uuid, "component_release") if collectionVersion == 1 else None
    return not_found() if found is None else to_wire(tea.component_collection(*found))


# --- CLE: PyPI publishes no lifecycle data, and TEA 1.0.0 makes CLE optional ---


def _no_cle(kind: str) -> Callable[[str], Awaitable[JSONResponse]]:
    async def get_cle(uuid: str) -> JSONResponse:
        known = await _entity(uuid, kind) is not None
        return not_found(ErrorType.NOT_IMPLEMENTED if known else ErrorType.OBJECT_UNKNOWN)

    return get_cle


for _path, _kind in (
    ("/product/{uuid}/cle", "product"),
    ("/productRelease/{uuid}/cle", "product_release"),
    ("/component/{uuid}/cle", "component"),
    ("/componentRelease/{uuid}/cle", "component_release"),
):
    router.add_api_route(_path, _no_cle(_kind), methods=["GET"])


# --- artifacts ---
#
# A wheel never changes, so each SBOM in one has exactly one revision, version 1, and "latest" is it.


async def _sbom_download(uuid: str, headers: dict[str, str] | None = None) -> Response:
    found = await read(store.get_sbom_content, uuid)
    if found is None:
        return not_found()
    content, media_type = found
    if analytics.enabled():
        entity = await read(store.get_entity, uuid)
        analytics.capture(
            "sbom_downloaded",
            {
                "artifact_uuid": uuid,
                "package": entity.name if entity else None,
                "version": entity.version if entity else None,
                "media_type": media_type,
                "size_bytes": len(content),
            },
        )
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/artifact/{uuid}/download")
async def download_artifact(uuid: str) -> Response:
    """Not TEA: the stable SBOM link package pages give."""
    return await _sbom_download(uuid)


async def _artifact(uuid: str, version: int | None) -> tuple[ReleaseRecord, SbomRecord] | None:
    found = await _component(uuid, "artifact") if version in (None, 1) else None
    if found is None:
        return None
    release, wheel = found
    sbom = next((s for s in wheel.sboms if s.uuid == uuid), None)
    return None if sbom is None else (release, sbom)


@router.get("/artifact/{uuid}/latest")
async def get_latest_artifact(uuid: str) -> Any:
    found = await _artifact(uuid, None)
    return not_found() if found is None else to_wire(tea.artifact(*found))


def _media_type_key(value: str) -> tuple[str, frozenset[tuple[str, str]]]:
    """A media type as TEA compares them: type, subtype and parameter names ignore case, values must match."""
    base, *params = value.split(";")
    pairs = (param.split("=", 1) for param in params if "=" in param)
    return base.strip().lower(), frozenset((k.strip().lower(), v.strip().strip('"')) for k, v in pairs)


def _etag_matches(if_none_match: str | None, etag: str) -> bool:
    """If-None-Match by RFC 9110's weak comparison."""
    if if_none_match is None:
        return False
    tags = [tag.strip().removeprefix("W/") for tag in if_none_match.split(",")]
    return "*" in tags or etag in tags


async def _download(
    request: Request, uuid: str, version: int | None, media_type: str | None, *, signature: bool
) -> Response:
    """The content of an artifact revision's one format, or the 404 for its signature: there are none."""
    found = await _artifact(uuid, version)
    if found is None:
        return not_found()
    _, sbom = found
    if media_type is not None and _media_type_key(media_type) != _media_type_key(sbom.media_type):
        return _error(406, ErrorType.NO_ACCEPTABLE_FORMAT, f"The artifact's only format is {sbom.media_type}")
    if signature:
        return not_found(ErrorType.SIGNATURE_NOT_FOUND)
    headers = {"ETag": f'"{sbom.sha256}"', "Content-Location": tea.artifact_download_url(uuid, sbom.media_type)}
    if version is None:
        # The latest revision may change, so a cache revalidates it (TEA 1.0.0); version 1 never does.
        headers["Cache-Control"] = "public, no-cache"
    if _etag_matches(request.headers.get("if-none-match"), headers["ETag"]):
        return Response(status_code=304, headers=headers)
    return await _sbom_download(uuid, headers)


MEDIA_TYPE = Query(None, max_length=255, description="The mediaType of the format to download")


@router.get("/artifact/{uuid}/latest/download")
async def download_latest_artifact(request: Request, uuid: str, mediaType: str | None = MEDIA_TYPE) -> Response:
    return await _download(request, uuid, None, mediaType, signature=False)


@router.get("/artifact/{uuid}/latest/signature/download")
async def download_latest_artifact_signature(
    request: Request, uuid: str, mediaType: str | None = MEDIA_TYPE
) -> Response:
    return await _download(request, uuid, None, mediaType, signature=True)


@router.get("/artifact/{uuid}/{artifactVersion}")
async def get_artifact_by_version(uuid: str, artifactVersion: int) -> Any:
    found = await _artifact(uuid, artifactVersion)
    return not_found() if found is None else to_wire(tea.artifact(*found))


@router.get("/artifact/{uuid}/{artifactVersion}/download")
async def download_artifact_by_version(
    request: Request, uuid: str, artifactVersion: int, mediaType: str | None = MEDIA_TYPE
) -> Response:
    return await _download(request, uuid, artifactVersion, mediaType, signature=False)


@router.get("/artifact/{uuid}/{artifactVersion}/signature/download")
async def download_artifact_signature_by_version(
    request: Request, uuid: str, artifactVersion: int, mediaType: str | None = MEDIA_TYPE
) -> Response:
    return await _download(request, uuid, artifactVersion, mediaType, signature=True)


# --- attestation (non-TEA) ---


@router.get("/attestation/{package}/{version}")
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

import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from libtea.models import (
    Artifact,
    ArtifactFormat,
    ArtifactType,
    Checksum,
    ChecksumAlgorithm,
    Collection,
    CollectionBelongsTo,
    CollectionUpdateReason,
    CollectionUpdateReasonType,
    Component,
    ComponentRef,
    ComponentReleaseWithCollection,
    DiscoveryInfo,
    Identifier,
    IdentifierType,
    Product,
    ProductRelease,
    Release,
    ReleaseDistribution,
    TeaServerInfo,
)
from packageurl import PackageURL

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.services.pypi import WheelInfo, extract_wheel_urls, filter_wheels_by_platform, get_version_metadata
from pypi_tea.services.sbom_extractor import extract_sboms
from pypi_tea.services.sbom_format import detect_sbom_format, validate_sbom
from pypi_tea.services.uuids import (
    artifact_uuid,
    component_release_uuid,
    component_uuid,
    product_release_uuid,
    product_uuid,
)

logger = logging.getLogger("pypi_tea.mapper")


@dataclass(frozen=True)
class PurlQualifiers:
    os_name: str | None = None
    arch: str | None = None


def parse_purl(purl_str: str) -> tuple[str, str | None, PurlQualifiers]:
    purl = PackageURL.from_string(purl_str)
    if purl.type != "pypi":
        raise ValueError(f"Only PyPI PURLs are supported, got: {purl.type}")
    qualifiers = purl.qualifiers or {}
    return (
        purl.name.lower(),
        purl.version,
        PurlQualifiers(os_name=qualifiers.get("os"), arch=qualifiers.get("arch")),
    )


def _make_checksums(digests: dict[str, str]) -> tuple[Checksum, ...]:
    mapping = {
        "sha256": ChecksumAlgorithm.SHA_256,
        "md5": ChecksumAlgorithm.MD5,
        "sha384": ChecksumAlgorithm.SHA_384,
        "sha512": ChecksumAlgorithm.SHA_512,
        "blake2b_256": ChecksumAlgorithm.BLAKE2B_256,
    }
    result = []
    for alg_name, value in digests.items():
        alg = mapping.get(alg_name.lower())
        if alg:
            result.append(Checksum(algType=alg, algValue=value))
    return tuple(result)


async def _get_metadata_cached(client: httpx.AsyncClient, cache: Cache, package: str, version: str) -> dict[str, Any]:
    cached = await cache.get_pypi_metadata(package, version)
    if cached:
        return cached
    metadata = await get_version_metadata(client, package, version)
    await cache.set_pypi_metadata(package, version, metadata)
    return metadata


async def _track_sbom_formats(cache: Cache, wheel_url: str, sboms: list[dict[str, Any]]) -> None:
    """Track SBOM formats, validation, and encoding, deduplicated by wheel_url:path."""
    for sbom in sboms:
        content = sbom["content"]
        media_type = sbom["media_type"]
        fmt, _mt = detect_sbom_format(content)
        if fmt:
            sbom_id = f"{wheel_url}:{sbom['path']}"
            await cache.track_sbom_format(sbom_id, fmt)
            await cache.track_sbom_encoding(sbom_id, media_type)
            valid = validate_sbom(content, fmt, media_type)
            await cache.track_sbom_validation(sbom_id, valid)


async def _get_sboms_for_wheel(cache: Cache, wheel: WheelInfo) -> list[dict[str, Any]]:
    if await cache.is_negative_cached(wheel.url):
        return []
    cached = await cache.get_sbom_content(wheel.url)
    if cached is not None:
        return cached
    sbom_files = await extract_sboms(wheel.url, wheel_size=wheel.size)
    if not sbom_files:
        await cache.set_negative_cache(wheel.url)
        return []
    result = [
        {
            "path": s.path,
            "content": s.content,
            "media_type": s.media_type,
            "sha256": hashlib.sha256(s.content.encode()).hexdigest(),
        }
        for s in sbom_files
    ]
    await cache.set_sbom_content(wheel.url, result)
    await _track_sbom_formats(cache, wheel.url, result)
    return result


def _build_product(name: str, version: str | None) -> Product:
    identifiers = (Identifier(id_type=IdentifierType.PURL, id_value=f"pkg:pypi/{name}"),)
    return Product(
        uuid=product_uuid(name),
        name=name,
        identifiers=identifiers,
    )


def _build_artifact(wheel: WheelInfo, sbom: dict[str, Any]) -> Artifact:
    a_uuid = artifact_uuid(wheel.url, sbom["path"])
    sbom_filename = sbom["path"].split("/")[-1]
    artifact_url = f"{settings.server_root_url}/v{settings.tea_spec_version}/artifact/{a_uuid}/download"
    checksums: tuple[Checksum, ...] = ()
    sha256 = sbom.get("sha256")
    if sha256:
        checksums = (Checksum(algType=ChecksumAlgorithm.SHA_256, algValue=sha256),)
    return Artifact(
        uuid=a_uuid,
        name=sbom_filename,
        type=ArtifactType.BOM,
        formats=(
            ArtifactFormat(
                media_type=sbom["media_type"],
                url=artifact_url,
                checksums=checksums,
            ),
        ),
    )


def _build_component(wheel: WheelInfo) -> Component:
    return Component(
        uuid=component_uuid(wheel.filename),
        name=wheel.filename,
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=wheel.url),),
    )


def _build_release_for_component(wheel: WheelInfo, version: str, created_date: datetime) -> Release:
    return Release(
        uuid=component_release_uuid(wheel.url),
        component=component_uuid(wheel.filename),
        component_name=wheel.filename,
        version=version,
        created_date=created_date,
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=wheel.url),),
        distributions=(
            ReleaseDistribution(
                distribution_type="wheel",
                url=wheel.url,
                checksums=_make_checksums(wheel.digests),
            ),
        ),
    )


async def _store_uuid_lookups(
    cache: Cache, name: str, version: str, wheels: list[WheelInfo], sboms_by_wheel: dict[str, list[dict[str, Any]]]
) -> None:
    await cache.set_uuid_lookup(product_uuid(name), "product", {"name": name})
    await cache.set_uuid_lookup(
        product_release_uuid(name, version), "product_release", {"name": name, "version": version}
    )
    for wheel in wheels:
        await cache.set_uuid_lookup(
            component_uuid(wheel.filename), "component", {"filename": wheel.filename, "url": wheel.url}
        )
        await cache.set_uuid_lookup(
            component_release_uuid(wheel.url),
            "component_release",
            {"filename": wheel.filename, "url": wheel.url, "name": name, "version": version},
        )
        for sbom in sboms_by_wheel.get(wheel.url, []):
            await cache.set_uuid_lookup(
                artifact_uuid(wheel.url, sbom["path"]),
                "artifact",
                {"wheel_url": wheel.url, "sbom_path": sbom["path"], "name": name, "version": version},
            )


async def resolve_purl(
    client: httpx.AsyncClient, cache: Cache, purl_str: str
) -> tuple[str, str, dict[str, Any], list[WheelInfo], dict[str, list[dict[str, Any]]]]:
    name, version, qualifiers = parse_purl(purl_str)
    if not version:
        raise ValueError("PURL must include a version (e.g. pkg:pypi/requests@2.31.0)")
    metadata = await _get_metadata_cached(client, cache, name, version)
    all_wheels = extract_wheel_urls(metadata)
    wheels = filter_wheels_by_platform(all_wheels, qualifiers.os_name, qualifiers.arch)
    sboms_by_wheel: dict[str, list[dict[str, Any]]] = {}
    for wheel in wheels:
        sboms = await _get_sboms_for_wheel(cache, wheel)
        if sboms:
            sboms_by_wheel[wheel.url] = sboms
    await _store_uuid_lookups(cache, name, version, all_wheels, sboms_by_wheel)
    await cache.track_package_query(name, version, has_sbom=bool(sboms_by_wheel))
    await cache.track_query(name, version, qualifiers.os_name, qualifiers.arch, has_sbom=bool(sboms_by_wheel))
    return name, version, metadata, wheels, sboms_by_wheel


def build_discovery_info(name: str, version: str) -> list[DiscoveryInfo]:
    return [
        DiscoveryInfo(
            product_release_uuid=product_release_uuid(name, version),
            servers=(
                TeaServerInfo(
                    root_url=settings.server_root_url,
                    versions=(settings.tea_spec_version,),
                ),
            ),
        )
    ]


def build_product_release(
    name: str,
    version: str,
    metadata: dict[str, Any],
    wheels: list[WheelInfo],
    sboms_by_wheel: dict[str, list[dict[str, Any]]],
) -> ProductRelease:
    urls = metadata.get("urls", [])
    upload_time = urls[0].get("upload_time_iso_8601") if urls else None
    created = datetime.fromisoformat(upload_time) if upload_time else datetime.now(UTC)
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)

    component_refs = tuple(
        ComponentRef(uuid=component_uuid(w.filename), release=component_release_uuid(w.url)) for w in wheels
    )

    return ProductRelease(
        uuid=product_release_uuid(name, version),
        product=product_uuid(name),
        product_name=name,
        version=version,
        created_date=created,
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=f"pkg:pypi/{name}@{version}"),),
        components=component_refs,
    )


def build_collection_for_product_release(
    name: str, version: str, wheels: list[WheelInfo], sboms_by_wheel: dict[str, list[dict[str, Any]]]
) -> Collection:
    artifacts = []
    for wheel in wheels:
        for sbom in sboms_by_wheel.get(wheel.url, []):
            artifacts.append(_build_artifact(wheel, sbom))
    return Collection(
        uuid=product_release_uuid(name, version),
        version=1,
        date=datetime.now(UTC),
        belongs_to=CollectionBelongsTo.PRODUCT_RELEASE,
        update_reason=CollectionUpdateReason(type=CollectionUpdateReasonType.INITIAL_RELEASE),
        artifacts=tuple(artifacts),
    )


def build_component_release_with_collection(
    wheel: WheelInfo, version: str, metadata: dict[str, Any], sboms: list[dict[str, Any]]
) -> ComponentReleaseWithCollection:
    urls = metadata.get("urls", [])
    upload_time = urls[0].get("upload_time_iso_8601") if urls else None
    created = datetime.fromisoformat(upload_time) if upload_time else datetime.now(UTC)
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)

    release = _build_release_for_component(wheel, version, created)
    artifacts = tuple(_build_artifact(wheel, sbom) for sbom in sboms)
    collection = Collection(
        uuid=component_release_uuid(wheel.url),
        version=1,
        date=datetime.now(UTC),
        belongs_to=CollectionBelongsTo.COMPONENT_RELEASE,
        update_reason=CollectionUpdateReason(type=CollectionUpdateReasonType.INITIAL_RELEASE),
        artifacts=artifacts,
    )
    return ComponentReleaseWithCollection(release=release, latest_collection=collection)

"""Build TEA 1.0.0 (libtea) models from stored records. Pure functions, no I/O.

Serialize them with `libtea.server.to_wire`, which drops unset fields and flattens a
component release the way TEA 1.0.0 defines it.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

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
    ProductReleaseWithCollection,
    Release,
    ReleaseDistribution,
    TeaServerInfo,
)
from packageurl import PackageURL
from packaging.utils import canonicalize_name

from pypi_tea.config import TEA_VERSION, settings
from pypi_tea.models import ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.services.uuids import (
    component_release_uuid,
    component_uuid,
    distribution_uuid,
    product_release_uuid,
    product_uuid,
)

TEA_PREFIX = f"/v{TEA_VERSION}"

# PyPI's digests that TEA 1.0.0 has an algorithm for (it dropped MD5).
_CHECKSUM_ALGS = {
    "sha256": ChecksumAlgorithm.SHA_256,
    "sha384": ChecksumAlgorithm.SHA_384,
    "sha512": ChecksumAlgorithm.SHA_512,
    "blake2b_256": ChecksumAlgorithm.BLAKE2B_256,
}


@dataclass(frozen=True)
class PurlQualifiers:
    os_name: str | None = None
    arch: str | None = None
    file_name: str | None = None


def parse_purl(purl_str: str) -> tuple[str, str | None, PurlQualifiers]:
    purl = PackageURL.from_string(purl_str)
    if purl.type != "pypi":
        raise ValueError(f"Only PyPI PURLs are supported, got: {purl.type}")
    qualifiers = purl.qualifiers or {}
    if not isinstance(qualifiers, dict):
        qualifiers = {}
    # PEP 503 normalisation, as PyPI does: `ruamel.yaml`, `Ruamel_YAML` and
    # `ruamel-yaml` are one project and must map to one set of rows and UUIDs.
    return (
        canonicalize_name(purl.name),
        purl.version,
        PurlQualifiers(
            os_name=qualifiers.get("os"), arch=qualifiers.get("arch"), file_name=qualifiers.get("file_name")
        ),
    )


def wheel_purl(name: str, version: str, filename: str) -> str:
    """The PURL of one wheel: its release's PURL with the `file_name` qualifier."""
    return PackageURL(type="pypi", name=name, version=version, qualifiers={"file_name": filename}).to_string()


def _checksums(digests: dict[str, str]) -> tuple[Checksum, ...]:
    return tuple(
        Checksum(algType=_CHECKSUM_ALGS[alg.lower()], algValue=value)
        for alg, value in digests.items()
        if alg.lower() in _CHECKSUM_ALGS
    )


def created(release: ReleaseRecord) -> datetime:
    """When pypi-tea first stored the release: TEA's createdDate, for the release and everything in it."""
    return datetime.fromtimestamp(release.first_seen or 0, UTC)


def release_date(uploaded: str | None) -> datetime | None:
    """When the release was uploaded to PyPI (ReleaseRecord.created): TEA's releaseDate."""
    if not uploaded:
        return None
    when = datetime.fromisoformat(uploaded)
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def artifact_download_url(uuid: str, media_type: str) -> str:
    """The versioned download URL of an artifact's one format, as TEA 1.0.0's Content-Location names it."""
    return f"{settings.server_root_url}{TEA_PREFIX}/artifact/{uuid}/1/download?mediaType={quote(media_type, safe='')}"


def product(name: str) -> Product:
    return Product(
        uuid=product_uuid(name),
        name=name,
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=f"pkg:pypi/{name}"),),
    )


def artifact(release: ReleaseRecord, sbom: SbomRecord) -> Artifact:
    """An SBOM shipped in a wheel. pypi-tea hosts the content, so its format has no url: TEA 1.0.0 clients
    fetch it from /artifact/{uuid}/{version}/download. Wheels never change, so each SBOM has one revision."""
    return Artifact(
        uuid=sbom.uuid,
        name=sbom.path.rsplit("/", 1)[-1],
        type=ArtifactType.BOM,
        version=1,
        created_date=created(release),
        formats=(
            ArtifactFormat(
                media_type=sbom.media_type,
                checksums=(Checksum(algType=ChecksumAlgorithm.SHA_256, algValue=sbom.sha256),),
            ),
        ),
    )


def component(name: str, version: str, filename: str) -> Component:
    return Component(
        uuid=component_uuid(filename),
        name=filename,
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=wheel_purl(name, version, filename)),),
    )


def component_release(release: ReleaseRecord, wheel: WheelRecord) -> Release:
    return Release(
        uuid=component_release_uuid(wheel.url),
        component=component_uuid(wheel.filename),
        component_name=wheel.filename,
        version=release.version,
        created_date=created(release),
        release_date=release_date(release.created),
        identifiers=(
            Identifier(id_type=IdentifierType.PURL, id_value=wheel_purl(release.name, release.version, wheel.filename)),
        ),
        distributions=(
            ReleaseDistribution(
                distribution_id=distribution_uuid(wheel.url), url=wheel.url, checksums=_checksums(wheel.digests)
            ),
        ),
    )


def _collection(
    uuid: str, release: ReleaseRecord, belongs_to: CollectionBelongsTo, artifacts: list[Artifact]
) -> Collection:
    # pypi-tea keeps no collection history, so every collection is version 1.
    return Collection(
        uuid=uuid,
        version=1,
        created_date=created(release),
        belongs_to=belongs_to,
        update_reason=CollectionUpdateReason(type=CollectionUpdateReasonType.INITIAL_RELEASE),
        artifacts=tuple(artifacts),
    )


def component_collection(release: ReleaseRecord, wheel: WheelRecord) -> Collection:
    return _collection(
        component_release_uuid(wheel.url),
        release,
        CollectionBelongsTo.COMPONENT_RELEASE,
        [artifact(release, s) for s in wheel.sboms],
    )


def component_release_with_collection(release: ReleaseRecord, wheel: WheelRecord) -> ComponentReleaseWithCollection:
    return ComponentReleaseWithCollection(
        release=component_release(release, wheel), latest_collection=component_collection(release, wheel)
    )


def product_collection(release: ReleaseRecord, wheels: list[WheelRecord] | None = None) -> Collection:
    wheels = release.wheels if wheels is None else wheels
    return _collection(
        product_release_uuid(release.name, release.version),
        release,
        CollectionBelongsTo.PRODUCT_RELEASE,
        [artifact(release, s) for w in wheels for s in w.sboms],
    )


def product_release(
    release: ReleaseRecord, wheels: list[WheelRecord] | None = None, *, with_collection: bool = False
) -> ProductRelease:
    """A product release; with its latest collection, as GET /productRelease/{uuid} answers, if asked."""
    wheels = release.wheels if wheels is None else wheels
    fields: dict[str, Any] = {
        "uuid": product_release_uuid(release.name, release.version),
        "product": product_uuid(release.name),
        "product_name": release.name,
        "version": release.version,
        "created_date": created(release),
        "release_date": release_date(release.created),
        "identifiers": (
            Identifier(id_type=IdentifierType.PURL, id_value=f"pkg:pypi/{release.name}@{release.version}"),
        ),
        "components": tuple(
            ComponentRef(uuid=component_uuid(w.filename), release=component_release_uuid(w.url)) for w in wheels
        ),
    }
    if with_collection:
        return ProductReleaseWithCollection(**fields, latest_collection=product_collection(release, wheels))
    return ProductRelease(**fields)


def discovery_info(name: str, version: str) -> list[DiscoveryInfo]:
    return [
        DiscoveryInfo(
            product_release_uuid=product_release_uuid(name, version),
            servers=(TeaServerInfo(root_url=settings.server_root_url, versions=(TEA_VERSION,)),),
        )
    ]

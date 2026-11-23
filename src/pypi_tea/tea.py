"""Build TEA (libtea) models from stored records. Pure functions, no I/O."""

from dataclasses import dataclass
from datetime import UTC, datetime

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

from pypi_tea.config import settings
from pypi_tea.models import ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.services.uuids import (
    component_release_uuid,
    component_uuid,
    distribution_uuid,
    product_release_uuid,
    product_uuid,
)

# The TEA API version this server speaks; it is served at the root and under /v1.0.0.
TEA_VERSION = "1.0.0"
# The older version also served, so existing clients keep working.
LEGACY_TEA_VERSION = "0.4.0"
TEA_VERSIONS = (TEA_VERSION, LEGACY_TEA_VERSION)

# TEA 1.0.0 dropped MD5, so PyPI's md5 digest is not published.
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
        PurlQualifiers(os_name=qualifiers.get("os"), arch=qualifiers.get("arch")),
    )


def _checksums(digests: dict[str, str]) -> tuple[Checksum, ...]:
    return tuple(
        Checksum(algType=_CHECKSUM_ALGS[alg.lower()], algValue=value)
        for alg, value in digests.items()
        if alg.lower() in _CHECKSUM_ALGS
    )


def _created(release: ReleaseRecord) -> datetime:
    if release.created:
        created = datetime.fromisoformat(release.created)
        return created if created.tzinfo else created.replace(tzinfo=UTC)
    return datetime(1970, 1, 1, tzinfo=UTC)


def product(name: str) -> Product:
    return Product(
        uuid=product_uuid(name),
        name=name,
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=f"pkg:pypi/{name}"),),
    )


def artifact(release: ReleaseRecord, sbom: SbomRecord, legacy: bool = False) -> Artifact:
    """An SBOM as a TEA artifact. Artifacts never change, so each has one version, 1."""
    if legacy:
        url = f"{settings.server_root_url}/v{LEGACY_TEA_VERSION}/artifact/{sbom.uuid}/download"
    else:
        url = f"{settings.server_root_url}/v{TEA_VERSION}/artifact/{sbom.uuid}/1/download"
    return Artifact(
        uuid=sbom.uuid,
        name=sbom.path.rsplit("/", 1)[-1],
        type=ArtifactType.BOM,
        version=1,
        created_date=_created(release),
        formats=(
            ArtifactFormat(
                media_type=sbom.media_type,
                url=url,
                checksums=(Checksum(algType=ChecksumAlgorithm.SHA_256, algValue=sbom.sha256),),
            ),
        ),
    )


def component(wheel: WheelRecord) -> Component:
    return Component(
        uuid=component_uuid(wheel.filename),
        name=wheel.filename,
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=wheel.url),),
    )


def component_release(release: ReleaseRecord, wheel: WheelRecord) -> Release:
    return Release(
        uuid=component_release_uuid(wheel.url),
        component=component_uuid(wheel.filename),
        component_name=wheel.filename,
        version=release.version,
        created_date=_created(release),
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=wheel.url),),
        distributions=(
            ReleaseDistribution(
                distribution_id=distribution_uuid(wheel.url),
                description="wheel",
                url=wheel.url,
                checksums=_checksums(wheel.digests),
            ),
        ),
    )


def component_collection(release: ReleaseRecord, wheel: WheelRecord, legacy: bool = False) -> Collection:
    return Collection(
        uuid=component_release_uuid(wheel.url),
        version=1,
        created_date=_created(release),
        belongs_to=CollectionBelongsTo.COMPONENT_RELEASE,
        update_reason=CollectionUpdateReason(type=CollectionUpdateReasonType.INITIAL_RELEASE),
        artifacts=tuple(artifact(release, s, legacy) for s in wheel.sboms),
    )


def component_release_with_collection(
    release: ReleaseRecord, wheel: WheelRecord, legacy: bool = False
) -> ComponentReleaseWithCollection:
    return ComponentReleaseWithCollection(
        release=component_release(release, wheel), latest_collection=component_collection(release, wheel, legacy)
    )


def product_release(release: ReleaseRecord, wheels: list[WheelRecord] | None = None) -> ProductRelease:
    wheels = release.wheels if wheels is None else wheels
    return ProductRelease(
        uuid=product_release_uuid(release.name, release.version),
        product=product_uuid(release.name),
        product_name=release.name,
        version=release.version,
        created_date=_created(release),
        identifiers=(Identifier(id_type=IdentifierType.PURL, id_value=f"pkg:pypi/{release.name}@{release.version}"),),
        components=tuple(
            ComponentRef(uuid=component_uuid(w.filename), release=component_release_uuid(w.url)) for w in wheels
        ),
    )


def product_collection(release: ReleaseRecord, legacy: bool = False) -> Collection:
    return Collection(
        uuid=product_release_uuid(release.name, release.version),
        version=1,
        created_date=_created(release),
        belongs_to=CollectionBelongsTo.PRODUCT_RELEASE,
        update_reason=CollectionUpdateReason(type=CollectionUpdateReasonType.INITIAL_RELEASE),
        artifacts=tuple(artifact(release, s, legacy) for w in release.wheels for s in w.sboms),
    )


def product_release_with_collection(release: ReleaseRecord) -> ProductReleaseWithCollection:
    """TEA 1.0.0's `/productRelease/{uuid}`: the release with its latest collection."""
    return ProductReleaseWithCollection(**dict(product_release(release)), latest_collection=product_collection(release))


def discovery_info(name: str, version: str) -> list[DiscoveryInfo]:
    return [
        DiscoveryInfo(
            product_release_uuid=product_release_uuid(name, version),
            servers=(TeaServerInfo(root_url=settings.server_root_url, versions=TEA_VERSIONS),),
        )
    ]

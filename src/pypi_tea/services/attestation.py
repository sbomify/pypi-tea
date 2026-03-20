import logging
from dataclasses import dataclass
from typing import Any

import httpx
from pypi_attestations import Distribution, Provenance, VerificationError

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.services.pypi import WheelInfo

logger = logging.getLogger("pypi_tea.attestation")


@dataclass(frozen=True)
class AttestationResult:
    status: str  # "verified" | "not_available" | "failed" | "disabled"
    publisher_kind: str | None = None  # "GitHub" | "GitLab" | "Google" | "CircleCI"
    repository: str | None = None
    workflow: str | None = None
    environment: str | None = None
    predicate_type: str | None = None
    certificate_claims: dict[str, str] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"status": self.status}
        if self.publisher_kind is not None:
            d["publisher_kind"] = self.publisher_kind
        if self.repository is not None:
            d["repository"] = self.repository
        if self.workflow is not None:
            d["workflow"] = self.workflow
        if self.environment is not None:
            d["environment"] = self.environment
        if self.predicate_type is not None:
            d["predicate_type"] = self.predicate_type
        if self.certificate_claims is not None:
            d["certificate_claims"] = self.certificate_claims
        if self.error is not None:
            d["error"] = self.error
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AttestationResult:
        return cls(
            status=d["status"],
            publisher_kind=d.get("publisher_kind"),
            repository=d.get("repository"),
            workflow=d.get("workflow"),
            environment=d.get("environment"),
            predicate_type=d.get("predicate_type"),
            certificate_claims=d.get("certificate_claims"),
            error=d.get("error"),
        )


_DISABLED_RESULT = AttestationResult(status="disabled")
_NOT_AVAILABLE_RESULT = AttestationResult(status="not_available")


async def fetch_provenance(
    client: httpx.AsyncClient, package: str, version: str, filename: str
) -> dict[str, Any] | None:
    """Fetch PEP 740 provenance from PyPI's integrity API. Returns JSON dict on 200, None otherwise."""
    url = f"{settings.pypi_base_url}/integrity/{package}/{version}/{filename}/provenance"
    try:
        resp = await client.get(url, headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
    except httpx.HTTPError as e:
        logger.warning("Failed to fetch provenance for %s: %s", filename, e)
        return None

    if resp.status_code == 200:
        return resp.json()  # type: ignore[no-any-return]
    if resp.status_code == 404:
        logger.debug("No provenance available for %s", filename)
        return None
    logger.warning("Provenance fetch for %s returned status %d", filename, resp.status_code)
    return None


def verify_provenance(provenance_data: dict[str, Any], filename: str, sha256_digest: str) -> AttestationResult:
    """Verify a PEP 740 provenance object. Returns result for the first successfully verified attestation."""
    provenance = Provenance.model_validate(provenance_data)
    dist = Distribution(name=filename, digest=sha256_digest)

    for bundle in provenance.attestation_bundles:
        publisher = bundle.publisher
        for attestation in bundle.attestations:
            try:
                predicate_type, _predicate = attestation.verify(identity=publisher, dist=dist)
            except VerificationError as e:
                logger.warning("Attestation verification failed for %s: %s", filename, e)
                return AttestationResult(status="failed", error=str(e))
            except Exception as e:
                logger.warning("Unexpected error verifying attestation for %s: %s", filename, e)
                return AttestationResult(status="failed", error=str(e))

            # Extract publisher info
            repository: str | None = getattr(publisher, "repository", None)
            workflow: str | None = getattr(publisher, "workflow", None) or getattr(publisher, "workflow_filepath", None)
            environment: str | None = getattr(publisher, "environment", None)

            # Extract certificate claims
            try:
                cert_claims = attestation.certificate_claims
            except Exception:
                cert_claims = None

            return AttestationResult(
                status="verified",
                publisher_kind=publisher.kind,
                repository=repository,
                workflow=workflow,
                environment=environment,
                predicate_type=predicate_type,
                certificate_claims=cert_claims,
            )

    return AttestationResult(status="not_available")


async def check_wheel_attestation(
    client: httpx.AsyncClient, cache: Cache, package: str, version: str, wheel: WheelInfo
) -> AttestationResult:
    """Check PEP 740 attestation for a wheel. Non-blocking: returns a result even on errors."""
    if not settings.attestation_verification:
        return _DISABLED_RESULT

    # Check cache
    cached = await cache.get_attestation(wheel.url)
    if cached is not None:
        return AttestationResult.from_dict(cached)

    try:
        provenance_data = await fetch_provenance(client, package, version, wheel.filename)
        if provenance_data is None:
            result = _NOT_AVAILABLE_RESULT
        else:
            sha256 = wheel.digests.get("sha256")
            if not sha256:
                result = AttestationResult(status="failed", error="No SHA-256 digest available for wheel")
            else:
                result = verify_provenance(provenance_data, wheel.filename, sha256)
    except Exception as e:
        logger.error("Unexpected error checking attestation for %s: %s", wheel.filename, e)
        result = AttestationResult(status="failed", error=str(e))

    # Cache and track
    await cache.set_attestation(wheel.url, result.to_dict())
    await cache.track_attestation_status(wheel.url, result.status)
    if result.publisher_kind:
        await cache.track_attestation_publisher(wheel.url, result.publisher_kind)

    return result

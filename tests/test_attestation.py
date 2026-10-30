import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from pypi_tea.services.attestation import (
    AttestationResult,
    check_wheel_attestation,
    fetch_provenance,
    verify_provenance,
)
from pypi_tea.services.pypi import WheelInfo

SAMPLE_WHEEL = WheelInfo(
    filename="cryptography-44.0.3-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    url="https://files.pythonhosted.org/packages/cryptography-44.0.3-cp39-abi3-manylinux_2_17_x86_64.whl",
    digests={"sha256": "abc123def456"},
    size=5000000,
)

SAMPLE_PROVENANCE = {
    "version": 1,
    "attestation_bundles": [
        {
            "publisher": {
                "kind": "GitHub",
                "repository": "pyca/cryptography",
                "workflow": "release.yml",
                "environment": "pypi",
            },
            "attestations": [
                {
                    "version": 1,
                    "verification_material": {
                        "certificate": "AAAA",
                        "transparency_entries": [
                            {
                                "logIndex": 1,
                                "logId": "test",
                                "integratedTime": 1,
                                "inclusionPromise": "",
                                "inclusionProof": None,
                                "signedEntryTimestamp": "",
                                "kindVersion": {"kind": "test", "version": "0.0.1"},
                                "body": "",
                            }
                        ],
                    },
                    "envelope": {
                        "statement": "AAAA",
                        "signature": "AAAA",
                    },
                }
            ],
        }
    ],
}


# --- fetch_provenance tests ---


def test_fetch_provenance_200():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_PROVENANCE

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = mock_resp

    result = asyncio.run(fetch_provenance(client, "cryptography", "44.0.3", SAMPLE_WHEEL.filename))
    assert result == SAMPLE_PROVENANCE
    client.get.assert_called_once()
    call_args = client.get.call_args
    assert "/integrity/cryptography/44.0.3/" in call_args[0][0]


def test_fetch_provenance_404():
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = mock_resp

    result = asyncio.run(fetch_provenance(client, "requests", "2.31.0", "requests-2.31.0-py3-none-any.whl"))
    assert result is None


def test_fetch_provenance_server_error_raises_for_retry():
    """A 5xx must not be recorded as "no provenance" — the ingest job retries instead."""
    request = httpx.Request("GET", "https://pypi.org/integrity/pkg/1.0.0/x.whl/provenance")
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = httpx.Response(503, request=request)

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(fetch_provenance(client, "pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl"))


def test_fetch_provenance_http_error_propagates():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.ConnectError("connection refused")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(fetch_provenance(client, "pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl"))


# --- verify_provenance tests ---


@patch("pypi_tea.services.attestation.Provenance")
def test_verify_provenance_verified(mock_provenance_cls):
    mock_attestation = MagicMock()
    mock_attestation.verify.return_value = ("https://docs.pypi.org/attestations/publish/v1", None)
    mock_attestation.certificate_claims = {"1.3.6.1.4.1.57264.1.12": "https://github.com/pyca/cryptography"}

    mock_publisher = MagicMock()
    mock_publisher.kind = "GitHub"
    mock_publisher.repository = "pyca/cryptography"
    mock_publisher.workflow = "release.yml"
    mock_publisher.environment = "pypi"

    mock_bundle = MagicMock()
    mock_bundle.publisher = mock_publisher
    mock_bundle.attestations = [mock_attestation]

    mock_provenance = MagicMock()
    mock_provenance.attestation_bundles = [mock_bundle]
    mock_provenance_cls.model_validate.return_value = mock_provenance

    result = verify_provenance(SAMPLE_PROVENANCE, SAMPLE_WHEEL.filename, "abc123def456")

    assert result.status == "verified"
    assert result.publisher_kind == "GitHub"
    assert result.repository == "pyca/cryptography"
    assert result.workflow == "release.yml"
    assert result.environment == "pypi"
    assert result.predicate_type == "https://docs.pypi.org/attestations/publish/v1"
    assert result.certificate_claims is not None


@patch("pypi_tea.services.attestation.Provenance")
def test_verify_provenance_failed(mock_provenance_cls):
    from pypi_attestations import VerificationError

    mock_attestation = MagicMock()
    mock_attestation.verify.side_effect = VerificationError("bad signature")

    mock_publisher = MagicMock()
    mock_publisher.kind = "GitHub"

    mock_bundle = MagicMock()
    mock_bundle.publisher = mock_publisher
    mock_bundle.attestations = [mock_attestation]

    mock_provenance = MagicMock()
    mock_provenance.attestation_bundles = [mock_bundle]
    mock_provenance_cls.model_validate.return_value = mock_provenance

    result = verify_provenance(SAMPLE_PROVENANCE, SAMPLE_WHEEL.filename, "abc123def456")

    assert result.status == "failed"
    assert result.error is not None


@patch("pypi_tea.services.attestation.Provenance")
def test_verify_provenance_empty_bundles(mock_provenance_cls):
    mock_provenance = MagicMock()
    mock_provenance.attestation_bundles = []
    mock_provenance_cls.model_validate.return_value = mock_provenance

    result = verify_provenance({}, SAMPLE_WHEEL.filename, "abc123def456")
    assert result.status == "not_available"


# --- check_wheel_attestation tests ---

SHA = SAMPLE_WHEEL.digests["sha256"]


def _settings(enabled: bool = True):
    patcher = patch("pypi_tea.services.attestation.settings")
    mock_settings = patcher.start()
    mock_settings.attestation_verification = enabled
    mock_settings.pypi_base_url = "https://pypi.org"
    return patcher


def test_check_wheel_attestation_disabled():
    client = AsyncMock(spec=httpx.AsyncClient)
    patcher = _settings(enabled=False)
    try:
        result = asyncio.run(check_wheel_attestation(client, "cryptography", "44.0.3", SAMPLE_WHEEL.filename, SHA))
    finally:
        patcher.stop()
    assert result.status == "disabled"
    client.get.assert_not_called()


def test_check_wheel_attestation_not_available():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = mock_resp
    patcher = _settings()
    try:
        result = asyncio.run(check_wheel_attestation(client, "requests", "2.31.0", SAMPLE_WHEEL.filename, SHA))
    finally:
        patcher.stop()
    assert result.status == "not_available"


def test_check_wheel_attestation_no_sha256():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_PROVENANCE
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = mock_resp
    patcher = _settings()
    try:
        result = asyncio.run(check_wheel_attestation(client, "pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl", None))
    finally:
        patcher.stop()
    assert result.status == "failed"
    assert "SHA-256" in (result.error or "")


def test_check_wheel_attestation_unexpected_error():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = RuntimeError("something went wrong")
    patcher = _settings()
    try:
        result = asyncio.run(check_wheel_attestation(client, "pkg", "1.0.0", SAMPLE_WHEEL.filename, SHA))
    finally:
        patcher.stop()
    assert result.status == "failed"
    assert result.error is not None


def test_check_wheel_attestation_transport_error_propagates():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.ReadTimeout("slow")
    patcher = _settings()
    try:
        with pytest.raises(httpx.ReadTimeout):
            asyncio.run(check_wheel_attestation(client, "pkg", "1.0.0", SAMPLE_WHEEL.filename, SHA))
    finally:
        patcher.stop()


# --- AttestationResult serialization tests ---


def test_attestation_result_roundtrip():
    result = AttestationResult(
        status="verified",
        publisher_kind="GitHub",
        repository="pyca/cryptography",
        workflow="release.yml",
        environment="pypi",
        predicate_type="https://docs.pypi.org/attestations/publish/v1",
        certificate_claims={"key": "value"},
    )
    d = result.to_dict()
    restored = AttestationResult.from_dict(d)
    assert restored == result


def test_attestation_result_minimal():
    result = AttestationResult(status="not_available")
    d = result.to_dict()
    assert d == {"status": "not_available"}
    restored = AttestationResult.from_dict(d)
    assert restored == result

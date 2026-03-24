import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import httpx

from pypi_tea.cache import Cache
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


def _make_cache() -> Cache:
    c = Cache.__new__(Cache)
    c._redis_url = "redis://fake"
    c._r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return c


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


def test_fetch_provenance_403():
    mock_resp = MagicMock()
    mock_resp.status_code = 403

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = mock_resp

    result = asyncio.run(fetch_provenance(client, "pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl"))
    assert result is None


def test_fetch_provenance_http_error():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.ConnectError("connection refused")

    result = asyncio.run(fetch_provenance(client, "pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl"))
    assert result is None


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


def test_check_wheel_attestation_disabled():
    cache = _make_cache()
    client = AsyncMock(spec=httpx.AsyncClient)
    with patch("pypi_tea.services.attestation.settings") as mock_settings:
        mock_settings.attestation_verification = False
        result = asyncio.run(check_wheel_attestation(client, cache, "cryptography", "44.0.3", SAMPLE_WHEEL))

    assert result.status == "disabled"


def test_check_wheel_attestation_cache_hit():
    async def _run():
        cache = _make_cache()
        cached_data = {"status": "verified", "publisher_kind": "GitHub", "repository": "pyca/cryptography"}
        await cache.set_attestation(SAMPLE_WHEEL.url, cached_data)

        client = AsyncMock(spec=httpx.AsyncClient)
        with patch("pypi_tea.services.attestation.settings") as mock_settings:
            mock_settings.attestation_verification = True
            result = await check_wheel_attestation(client, cache, "cryptography", "44.0.3", SAMPLE_WHEEL)

        assert result.status == "verified"
        assert result.publisher_kind == "GitHub"
        client.get.assert_not_called()

    asyncio.run(_run())


def test_check_wheel_attestation_not_available():
    async def _run():
        cache = _make_cache()
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = mock_resp

        with patch("pypi_tea.services.attestation.settings") as mock_settings:
            mock_settings.attestation_verification = True
            mock_settings.pypi_base_url = "https://pypi.org"
            result = await check_wheel_attestation(client, cache, "requests", "2.31.0", SAMPLE_WHEEL)

        assert result.status == "not_available"
        cached = await cache.get_attestation(SAMPLE_WHEEL.url)
        assert cached is not None
        assert cached["status"] == "not_available"

    asyncio.run(_run())


def test_check_wheel_attestation_no_sha256():
    async def _run():
        cache = _make_cache()
        wheel_no_sha = WheelInfo(
            filename="pkg-1.0.0-py3-none-any.whl",
            url="https://files.pythonhosted.org/packages/pkg-1.0.0-py3-none-any.whl",
            digests={"md5": "abc123"},
            size=1000,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_PROVENANCE

        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = mock_resp

        with patch("pypi_tea.services.attestation.settings") as mock_settings:
            mock_settings.attestation_verification = True
            mock_settings.pypi_base_url = "https://pypi.org"
            result = await check_wheel_attestation(client, cache, "pkg", "1.0.0", wheel_no_sha)

        assert result.status == "failed"
        assert "SHA-256" in (result.error or "")

    asyncio.run(_run())


def test_check_wheel_attestation_unexpected_error():
    async def _run():
        cache = _make_cache()
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.side_effect = RuntimeError("something went wrong")

        with patch("pypi_tea.services.attestation.settings") as mock_settings:
            mock_settings.attestation_verification = True
            mock_settings.pypi_base_url = "https://pypi.org"
            result = await check_wheel_attestation(client, cache, "pkg", "1.0.0", SAMPLE_WHEEL)

        assert result.status == "failed"
        assert result.error is not None

    asyncio.run(_run())


# --- Stats tracking tests ---


def test_attestation_stats_tracking():
    async def _run():
        cache = _make_cache()
        await cache.track_attestation_status("wheel1", "verified")
        await cache.track_attestation_publisher("wheel1", "GitHub")

        stats = await cache.get_stats()
        assert stats["attestations"]["verified"] == 1
        assert stats["attestation_publishers"]["GitHub"] == 1

    asyncio.run(_run())


def test_attestation_stats_idempotent():
    async def _run():
        cache = _make_cache()
        await cache.track_attestation_status("wheel1", "verified")
        await cache.track_attestation_status("wheel1", "verified")

        stats = await cache.get_stats()
        assert stats["attestations"]["verified"] == 1

    asyncio.run(_run())


def test_attestation_stats_correction():
    async def _run():
        cache = _make_cache()
        await cache.track_attestation_status("wheel1", "not_available")
        stats = await cache.get_stats()
        assert stats["attestations"]["not_available"] == 1

        await cache.track_attestation_status("wheel1", "verified")
        stats = await cache.get_stats()
        assert stats["attestations"]["verified"] == 1
        assert stats["attestations"].get("not_available", 0) == 0

    asyncio.run(_run())


def test_attestation_publisher_stats_multiple():
    async def _run():
        cache = _make_cache()
        await cache.track_attestation_publisher("wheel1", "GitHub")
        await cache.track_attestation_publisher("wheel2", "GitHub")
        await cache.track_attestation_publisher("wheel3", "GitLab")

        stats = await cache.get_stats()
        assert stats["attestation_publishers"]["GitHub"] == 2
        assert stats["attestation_publishers"]["GitLab"] == 1

    asyncio.run(_run())


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

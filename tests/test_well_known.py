"""Tests for /.well-known/tea, version probe, versioned route prefix, and artifact download."""

import hashlib
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from libtea.discovery import purl_tei

from pypi_tea.config import settings

PURL = "pkg:pypi/libtea@0.4.0"
TEI = purl_tei("localhost", PURL)
LEGACY_TEI = f"urn:tei:purl:localhost:{PURL}"
# Each served prefix, the version it speaks, and a TEI in that version's form.
APIS = [
    ("/v1.0.0", "1.0.0", TEI),
    ("/v0.4.0", "0.4.0", LEGACY_TEI),
    ("/v0.3.0-beta.2", "0.4.0", LEGACY_TEI),
]


@pytest.fixture()
def client(tea_server: str) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=tea_server, timeout=10.0) as c:
        yield c


class TestWellKnownTea:
    def test_returns_valid_document(self, client: httpx.Client) -> None:
        resp = client.get("/.well-known/tea")
        assert resp.status_code == 200
        data = resp.json()
        assert data["schemaVersion"] == 1
        assert len(data["endpoints"]) >= 1

    def test_endpoint_has_url_and_version(self, client: httpx.Client) -> None:
        data = client.get("/.well-known/tea").json()
        ep = data["endpoints"][0]
        assert ep["url"] == settings.server_root_url
        assert ep["versions"] == ["1.0.0", "0.4.0"]
        assert ep["priority"] == 1.0

    def test_cache_header(self, client: httpx.Client) -> None:
        resp = client.get("/.well-known/tea")
        assert "max-age=3600" in resp.headers.get("cache-control", "")


@pytest.mark.parametrize(("prefix", "version", "tei"), APIS)
class TestVersionedRoutes:
    def test_head_returns_200(self, client: httpx.Client, prefix: str, version: str, tei: str) -> None:
        assert client.head(prefix).status_code == 200

    def test_get_returns_version(self, client: httpx.Client, prefix: str, version: str, tei: str) -> None:
        resp = client.get(prefix)
        assert resp.status_code == 200
        assert resp.json()["version"] == version

    def test_discovery(self, client: httpx.Client, prefix: str, version: str, tei: str) -> None:
        resp = client.get(f"{prefix}/discovery", params={"tei": tei})
        assert resp.status_code == 200
        assert resp.json()[0]["servers"][0]["versions"] == ["1.0.0", "0.4.0"]
        assert "max-age=3600" in resp.headers.get("cache-control", "")

    def test_product_404(self, client: httpx.Client, prefix: str, version: str, tei: str) -> None:
        """Unknown UUID gets a TEA 404, not a routing 404."""
        resp = client.get(f"{prefix}/product/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404
        assert resp.json() == {"error": "OBJECT_UNKNOWN"}


class TestUnversionedRoutes:
    def test_discovery_is_1_0_0(self, client: httpx.Client) -> None:
        assert client.get("/discovery", params={"tei": TEI}).status_code == 200
        assert client.get("/discovery", params={"purl": PURL}).status_code == 200

    def test_product_release_has_latest_collection(self, client: httpx.Client) -> None:
        [found] = client.get("/discovery", params={"purl": PURL}).json()
        release = client.get(f"/productRelease/{found['productReleaseUuid']}").json()
        assert release["latestCollection"]["artifacts"]


# Each version's artifact path and the download URL its formats carry.
ARTIFACT_APIS = [
    ("/v1.0.0", TEI, "/artifact/{}/latest", "/v1.0.0/artifact/{}/1/download"),
    ("/v0.4.0", LEGACY_TEI, "/artifact/{}", "/v0.4.0/artifact/{}/download"),
]


@pytest.mark.parametrize(("prefix", "tei", "artifact_path", "download_path"), ARTIFACT_APIS)
class TestArtifactDownload:
    def _artifact(self, client: httpx.Client, prefix: str, tei: str, artifact_path: str) -> dict[str, Any]:
        """Resolve the PURL and fetch the first artifact of its collection."""
        resp = client.get(f"{prefix}/discovery", params={"tei": tei})
        assert resp.status_code == 200
        pr_uuid = resp.json()[0]["productReleaseUuid"]
        resp = client.get(f"{prefix}/productRelease/{pr_uuid}/collection/latest")
        assert resp.status_code == 200
        artifacts = resp.json().get("artifacts", [])
        assert len(artifacts) > 0, "libtea@0.4.0 should have at least one SBOM artifact"
        resp = client.get(prefix + artifact_path.format(artifacts[0]["uuid"]))
        assert resp.status_code == 200
        artifact: dict[str, Any] = resp.json()
        return artifact

    def test_artifact_url_points_to_self(
        self, client: httpx.Client, prefix: str, tei: str, artifact_path: str, download_path: str
    ) -> None:
        """Artifact format URL should point to pypi-tea's download endpoint, not PyPI CDN."""
        artifact = self._artifact(client, prefix, tei, artifact_path)
        assert artifact["formats"][0]["url"] == settings.server_root_url + download_path.format(artifact["uuid"])

    def test_download_matches_sha256_checksum(
        self, client: httpx.Client, prefix: str, tei: str, artifact_path: str, download_path: str
    ) -> None:
        """The download is the SBOM, and its SHA-256 is the one the artifact format states."""
        artifact = self._artifact(client, prefix, tei, artifact_path)
        fmt = artifact["formats"][0]
        sha256 = next((c["algValue"] for c in fmt["checksums"] if c["algType"] == "SHA-256"), None)
        assert sha256 is not None, "artifact format should have a SHA-256 checksum"
        resp = client.get(download_path.format(artifact["uuid"]))
        assert resp.status_code == 200
        assert resp.headers["content-type"] == fmt["mediaType"]
        data = resp.json()
        assert "bomFormat" in data or "spdxVersion" in data
        assert hashlib.sha256(resp.content).hexdigest() == sha256

    def test_download_unknown_uuid_returns_404(
        self, client: httpx.Client, prefix: str, tei: str, artifact_path: str, download_path: str
    ) -> None:
        resp = client.get(download_path.format("00000000-0000-0000-0000-000000000000"))
        assert resp.status_code == 404

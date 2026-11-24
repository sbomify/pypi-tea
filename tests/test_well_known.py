"""Tests for /.well-known/tea, version probe, versioned route prefix, and artifact download, against live PyPI."""

import hashlib
from collections.abc import Iterator

import httpx
import pytest
from libtea.discovery import purl_tei

from pypi_tea.config import TEA_VERSION, settings

TEI = purl_tei("localhost", "pkg:pypi/libtea@0.4.0")
V = f"/v{TEA_VERSION}"


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
        assert ep["versions"] == ["1.0.0"]
        assert ep["priority"] == 1.0

    def test_cache_header(self, client: httpx.Client) -> None:
        resp = client.get("/.well-known/tea")
        assert "max-age=3600" in resp.headers.get("cache-control", "")


class TestVersionProbe:
    def test_head_returns_200(self, client: httpx.Client) -> None:
        resp = client.head(V)
        assert resp.status_code == 200

    def test_get_returns_version(self, client: httpx.Client) -> None:
        resp = client.get(V)
        assert resp.status_code == 200
        assert resp.json()["version"] == TEA_VERSION

    def test_old_version_prefix_is_gone(self, client: httpx.Client) -> None:
        assert client.get("/v0.3.0-beta.2/discovery", params={"tei": TEI}).status_code == 404


class TestVersionedRoutes:
    def test_discovery_under_version_prefix(self, client: httpx.Client) -> None:
        resp = client.get(f"{V}/discovery", params={"tei": TEI})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_discovery_unversioned_still_works(self, client: httpx.Client) -> None:
        resp = client.get("/discovery", params={"tei": TEI})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_versioned_product_404(self, client: httpx.Client) -> None:
        """Versioned route returns proper 404 for unknown UUID, not a routing 404."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"{V}/product/{fake_uuid}")
        assert resp.status_code == 404
        assert resp.json() == {"error": "OBJECT_UNKNOWN"}

    def test_versioned_cache_headers(self, client: httpx.Client) -> None:
        resp = client.get(f"{V}/discovery", params={"tei": TEI})
        assert "max-age=3600" in resp.headers.get("cache-control", "")


class TestArtifactDownload:
    def _artifact(self, client: httpx.Client) -> dict[str, object]:
        """Resolve the TEI and return the first artifact of the release's collection."""
        resp = client.get(f"{V}/discovery", params={"tei": TEI})
        assert resp.status_code == 200
        pr_uuid = resp.json()[0]["productReleaseUuid"]
        resp = client.get(f"{V}/productRelease/{pr_uuid}/collection/latest")
        assert resp.status_code == 200
        artifacts = resp.json()["artifacts"]
        assert artifacts, "libtea@0.4.0 should have at least one SBOM artifact"
        return dict(artifacts[0])

    def test_format_is_hosted_here(self, client: httpx.Client) -> None:
        """TEA 1.0.0: a format pypi-tea hosts has no url; clients fetch it from the download endpoint."""
        artifact = self._artifact(client)
        resp = client.get(f"{V}/artifact/{artifact['uuid']}/latest")
        assert resp.status_code == 200
        body = resp.json()
        assert body["version"] == 1
        assert "createdDate" in body
        assert "url" not in body["formats"][0]

    def test_download_matches_checksum(self, client: httpx.Client) -> None:
        artifact = self._artifact(client)
        fmt = client.get(f"{V}/artifact/{artifact['uuid']}/latest").json()["formats"][0]
        resp = client.get(f"{V}/artifact/{artifact['uuid']}/1/download", params={"mediaType": fmt["mediaType"]})
        assert resp.status_code == 200
        assert "json" in resp.headers["content-type"].lower()
        data = resp.json()
        assert "bomFormat" in data or "spdxVersion" in data
        sha256 = next(c for c in fmt["checksums"] if c["algType"] == "SHA-256")
        assert sha256["algValue"] == hashlib.sha256(resp.content).hexdigest()
        assert resp.headers["etag"] == f'"{sha256["algValue"]}"'

    def test_package_page_download_link_still_works(self, client: httpx.Client) -> None:
        artifact = self._artifact(client)
        resp = client.get(f"/artifact/{artifact['uuid']}/download")
        assert resp.status_code == 200

    def test_download_unknown_uuid_returns_404(self, client: httpx.Client) -> None:
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"{V}/artifact/{fake_uuid}/latest/download")
        assert resp.status_code == 404
        assert resp.json() == {"error": "OBJECT_UNKNOWN"}

"""Tests for /.well-known/tea, version probe, versioned route prefix, and artifact download."""

import httpx
import pytest

from pypi_tea.config import settings

TEI = "urn:tei:purl:localhost:pkg:pypi/libtea@0.4.0"
PURL = "pkg:pypi/libtea@0.4.0"


@pytest.fixture()
def client(tea_server):
    with httpx.Client(base_url=tea_server, timeout=10.0) as c:
        yield c


class TestWellKnownTea:
    def test_returns_valid_document(self, client: httpx.Client):
        resp = client.get("/.well-known/tea")
        assert resp.status_code == 200
        data = resp.json()
        assert data["schemaVersion"] == 1
        assert len(data["endpoints"]) >= 1

    def test_endpoint_has_url_and_version(self, client: httpx.Client):
        data = client.get("/.well-known/tea").json()
        ep = data["endpoints"][0]
        assert ep["url"] == settings.server_root_url
        assert settings.tea_spec_version in ep["versions"]
        assert ep["priority"] == 1.0

    def test_cache_header(self, client: httpx.Client):
        resp = client.get("/.well-known/tea")
        assert "max-age=3600" in resp.headers.get("cache-control", "")


class TestVersionProbe:
    def test_head_returns_200(self, client: httpx.Client):
        resp = client.head(f"/v{settings.tea_spec_version}")
        assert resp.status_code == 200

    def test_get_returns_version(self, client: httpx.Client):
        resp = client.get(f"/v{settings.tea_spec_version}")
        assert resp.status_code == 200
        assert resp.json()["version"] == settings.tea_spec_version


class TestVersionedRoutes:
    def test_discovery_under_version_prefix(self, client: httpx.Client):
        resp = client.get(f"/v{settings.tea_spec_version}/discovery", params={"tei": TEI})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_discovery_unversioned_still_works(self, client: httpx.Client):
        resp = client.get("/discovery", params={"tei": TEI})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_versioned_product_404(self, client: httpx.Client):
        """Versioned route returns proper 404 for unknown UUID, not a routing 404."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"/v{settings.tea_spec_version}/product/{fake_uuid}")
        assert resp.status_code == 404
        data = resp.json()
        assert "error" in data

    def test_versioned_cache_headers(self, client: httpx.Client):
        resp = client.get(f"/v{settings.tea_spec_version}/discovery", params={"tei": TEI})
        assert "max-age=3600" in resp.headers.get("cache-control", "")


class TestArtifactDownload:
    def _get_artifact_uuid(self, client: httpx.Client) -> str:
        """Resolve the PURL and find an artifact UUID from the collection."""
        prefix = f"/v{settings.tea_spec_version}"
        # Trigger resolution so UUIDs are cached
        resp = client.get(f"{prefix}/discovery", params={"tei": TEI})
        assert resp.status_code == 200
        discovery = resp.json()
        pr_uuid = discovery[0]["productReleaseUuid"]
        # Get the collection which contains artifacts
        resp = client.get(f"{prefix}/productRelease/{pr_uuid}/collection/latest")
        assert resp.status_code == 200
        collection = resp.json()
        artifacts = collection.get("artifacts", [])
        assert len(artifacts) > 0, "libtea@0.4.0 should have at least one SBOM artifact"
        return artifacts[0]["uuid"]

    def test_artifact_url_points_to_self(self, client: httpx.Client):
        """Artifact format URL should point to pypi-tea's download endpoint, not PyPI CDN."""
        a_uuid = self._get_artifact_uuid(client)
        resp = client.get(f"/v{settings.tea_spec_version}/artifact/{a_uuid}")
        assert resp.status_code == 200
        artifact = resp.json()
        url = artifact["formats"][0]["url"]
        assert "/artifact/" in url
        assert "/download" in url
        assert "files.pythonhosted.org" not in url

    def test_download_returns_sbom_content(self, client: httpx.Client):
        """GET /artifact/{uuid}/download should return actual SBOM content."""
        a_uuid = self._get_artifact_uuid(client)
        resp = client.get(f"/v{settings.tea_spec_version}/artifact/{a_uuid}/download")
        assert resp.status_code == 200
        assert (
            "cyclonedx" in resp.headers.get("content-type", "").lower()
            or "json" in resp.headers.get("content-type", "").lower()
        )
        data = resp.json()
        assert "bomFormat" in data or "spdxVersion" in data

    def test_artifact_has_sha256_checksum(self, client: httpx.Client):
        """Artifact format should include a SHA-256 checksum matching the SBOM content."""
        import hashlib

        a_uuid = self._get_artifact_uuid(client)
        resp = client.get(f"/v{settings.tea_spec_version}/artifact/{a_uuid}")
        assert resp.status_code == 200
        artifact = resp.json()
        fmt = artifact["formats"][0]
        checksums = fmt.get("checksums", [])
        assert len(checksums) > 0, "artifact format should have at least one checksum"
        sha256_entry = next((c for c in checksums if c["algType"] == "SHA-256"), None)
        assert sha256_entry is not None, "artifact format should have a SHA-256 checksum"

        # Verify the checksum matches the actual SBOM content
        download_resp = client.get(f"/v{settings.tea_spec_version}/artifact/{a_uuid}/download")
        assert download_resp.status_code == 200
        expected = hashlib.sha256(download_resp.content).hexdigest()
        assert sha256_entry["algValue"] == expected

    def test_download_unknown_uuid_returns_404(self, client: httpx.Client):
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        resp = client.get(f"/v{settings.tea_spec_version}/artifact/{fake_uuid}/download")
        assert resp.status_code == 404

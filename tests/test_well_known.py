"""Tests for /.well-known/tea, version probe, and versioned route prefix."""

import httpx
import pytest

from pypi_tea.config import settings

TEI = "urn:tei:purl:localhost:pkg:pypi/libtea@0.4.0"


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

"""Tests for SEO package pages, listing, sitemap, and robots.txt."""

from typing import Any
from xml.etree import ElementTree

import fakeredis.aioredis
import httpx
import pytest

from pypi_tea.app import app
from pypi_tea.cache import Cache


@pytest.fixture()
def fake_cache() -> Cache:
    cache = Cache.__new__(Cache)
    cache._redis_url = "redis://fake"
    cache._r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return cache


@pytest.fixture()
async def client(fake_cache: Cache) -> Any:
    transport = httpx.ASGITransport(app=app)
    # Save original state so session-scoped fixtures aren't corrupted
    orig_cache = getattr(app.state, "cache", None)
    orig_client = getattr(app.state, "http_client", None)
    app.state.cache = fake_cache
    app.state.http_client = httpx.AsyncClient()
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    await app.state.http_client.aclose()
    # Restore original state
    if orig_cache is not None:
        app.state.cache = orig_cache
    if orig_client is not None:
        app.state.http_client = orig_client


async def _seed_package(cache: Cache, name: str = "maturin", version: str = "1.8.1") -> None:
    """Seed a package with SBOM data into the cache."""
    metadata: dict[str, Any] = {
        "info": {
            "name": name,
            "version": version,
            "summary": "A fast Python build tool, written in Rust",
            "author": "Test Author",
            "license": "MIT",
            "requires_python": ">=3.8",
            "project_urls": {"Homepage": f"https://github.com/test/{name}"},
            "classifiers": ["Programming Language :: Python :: 3"],
        },
        "urls": [
            {
                "filename": f"{name}-{version}-cp311-cp311-manylinux_2_17_x86_64.whl",
                "url": f"https://files.pythonhosted.org/packages/{name}-{version}-cp311-cp311-manylinux_2_17_x86_64.whl",
                "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                "digests": {"sha256": "abc123"},
                "size": 1000000,
                "packagetype": "bdist_wheel",
            }
        ],
    }
    await cache.set_pypi_metadata(name, version, metadata)
    await cache.track_package_query(name, version, has_sbom=True)

    wheel_url = metadata["urls"][0]["url"]
    sbom_path = f"{name}-{version}.dist-info/sboms/bom.cdx.json"

    sbom = {
        "path": sbom_path,
        "content": '{"bomFormat":"CycloneDX","specVersion":"1.5"}',
        "media_type": "application/vnd.cyclonedx+json",
        "sha256": "def456",
    }
    await cache.set_sbom_content(wheel_url, [sbom])

    from pypi_tea.services.uuids import artifact_uuid, component_release_uuid, component_uuid

    a_uuid = artifact_uuid(wheel_url, sbom_path)
    await cache.set_uuid_lookup(
        a_uuid, "artifact", {"wheel_url": wheel_url, "sbom_path": sbom_path, "name": name, "version": version}
    )

    cr_uuid = component_release_uuid(wheel_url)
    filename = metadata["urls"][0]["filename"]
    await cache.set_uuid_lookup(
        cr_uuid, "component_release", {"filename": filename, "url": wheel_url, "name": name, "version": version}
    )

    c_uuid = component_uuid(filename)
    await cache.set_uuid_lookup(c_uuid, "component", {"filename": filename, "url": wheel_url})

    sbom_id = f"{wheel_url}:{sbom_path}"
    await cache.track_sbom_format(sbom_id, "CycloneDX/1.5")
    await cache.track_sbom_encoding(sbom_id, "application/vnd.cyclonedx+json")
    await cache.track_sbom_validation(sbom_id, True)
    await cache.track_package_format(name, version, "CycloneDX/1.5")


@pytest.fixture()
async def seeded_client(fake_cache: Cache, client: httpx.AsyncClient) -> Any:
    """Client with a pre-seeded package in cache."""
    await _seed_package(fake_cache)
    yield client


class TestPackagePage:
    @pytest.mark.anyio()
    async def test_package_not_found(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/package/nonexistent/1.0")
        assert resp.status_code == 404
        assert "Package Not Found" in resp.text

    @pytest.mark.anyio()
    async def test_package_page_renders(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/package/maturin/1.8.1")
        assert resp.status_code == 200
        html = resp.text

        # Title tag with SEO keywords
        assert "<title>SBOM for maturin 1.8.1" in html

        # Meta description
        assert 'name="description"' in html
        assert "maturin" in html

        # Canonical URL
        assert 'rel="canonical"' in html
        assert "/package/maturin/1.8.1" in html

        # Open Graph tags
        assert 'property="og:title"' in html
        assert 'property="og:url"' in html

        # Twitter Card
        assert 'name="twitter:card"' in html

        # JSON-LD structured data
        assert "application/ld+json" in html
        assert "SoftwareSourceCode" in html

        # Content
        assert "maturin" in html
        assert "1.8.1" in html
        assert "CycloneDX" in html
        assert "Download" in html

    @pytest.mark.anyio()
    async def test_package_page_has_cache_header(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/package/maturin/1.8.1")
        assert "max-age=3600" in resp.headers.get("cache-control", "")


class TestPackagesListing:
    @pytest.mark.anyio()
    async def test_empty_listing(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/packages")
        assert resp.status_code == 200
        assert "No packages found" in resp.text

    @pytest.mark.anyio()
    async def test_listing_with_packages(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/packages")
        assert resp.status_code == 200
        html = resp.text
        assert "maturin" in html
        assert "1.8.1" in html
        assert "/package/maturin/1.8.1" in html

    @pytest.mark.anyio()
    async def test_listing_title(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/packages")
        assert "<title>PyPI Packages with SBOMs" in resp.text

    @pytest.mark.anyio()
    async def test_filter_by_format(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/packages?format=CycloneDX")
        assert resp.status_code == 200
        assert "maturin" in resp.text
        assert "CycloneDX SBOMs" in resp.text

    @pytest.mark.anyio()
    async def test_filter_by_unknown_format(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/packages?format=UnknownFormat")
        assert resp.status_code == 200
        assert "No packages found" in resp.text

    @pytest.mark.anyio()
    async def test_listing_pagination(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/packages?page=2")
        assert resp.status_code == 200
        assert "No packages found" in resp.text or "Page 2" in resp.text


class TestSitemap:
    @pytest.mark.anyio()
    async def test_sitemap_xml(self, seeded_client: httpx.AsyncClient) -> None:
        resp = await seeded_client.get("/sitemap.xml")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/xml")

        root = ElementTree.fromstring(resp.text)
        ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        urls = [url.find("s:loc", ns).text for url in root.findall("s:url", ns)]  # type: ignore[union-attr]

        assert any(u.endswith("/") for u in urls)
        assert any("/packages" in u for u in urls)  # type: ignore[operator]
        assert any("/package/maturin/1.8.1" in u for u in urls)  # type: ignore[operator]

    @pytest.mark.anyio()
    async def test_empty_sitemap(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/sitemap.xml")
        assert resp.status_code == 200
        root = ElementTree.fromstring(resp.text)
        ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        urls = root.findall("s:url", ns)
        assert len(urls) == 2  # homepage + /packages


class TestRobotsTxt:
    @pytest.mark.anyio()
    async def test_robots_txt(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/robots.txt")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert "User-agent: *" in resp.text
        assert "Sitemap:" in resp.text
        assert "sitemap.xml" in resp.text

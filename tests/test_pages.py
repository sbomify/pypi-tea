"""HTML pages, listing, sitemap, robots, stats, and read-path backpressure."""

import asyncio
from collections.abc import AsyncIterator
from xml.etree import ElementTree

import httpx
import pytest

from conftest import FakePyPI, make_wheel, sbom_wheel
from pypi_tea import db, jobs, lookup, store
from pypi_tea.app import app
from pypi_tea.config import settings
from pypi_tea.ingest import ingest_release
from pypi_tea.routes import pages, seo

pytestmark = pytest.mark.anyio


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
async def client(database: str) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _seed(fake_pypi: FakePyPI, *releases: tuple[str, str, bool]) -> None:
    for name, version, with_sbom in releases:
        wheel = sbom_wheel(name, version) if with_sbom else make_wheel({f"{name}/__init__.py": b""})
        fake_pypi.add(name, version, [(f"{name}-{version}-py3-none-any.whl", wheel)])
    async with fake_pypi.client() as c:
        for name, version, _ in releases:
            await ingest_release(c, name, version)
    store.rebuild_listing(db.connect(settings.database_path))


async def test_package_page(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, ("maturin", "1.8.1", True))
    resp = await client.get("/package/maturin/1.8.1")
    assert resp.status_code == 200
    assert "SBOM for maturin" in resp.text
    assert "CycloneDX" in resp.text
    assert 'rel="nofollow"' in resp.text
    assert f"pypi-tea {pages._VERSION}" in resp.text
    assert "s-maxage" in resp.headers["cache-control"]


async def test_dashboard_and_static_assets(client: httpx.AsyncClient) -> None:
    resp = await client.get("/")
    assert resp.status_code == 200
    assert 'id="dashboard"' in resp.text
    assert "cdn.tailwindcss.com" not in resp.text
    for path in ("/static/css/site.css", "/static/fonts/figtree-latin.woff2", "/static/img/logo.svg"):
        asset = await client.get(path)
        assert asset.status_code == 200, path
        assert "s-maxage" in asset.headers["cache-control"]


async def test_package_page_without_sbom_is_404(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, ("plain", "1.0", False))
    resp = await client.get("/package/plain/1.0")
    assert resp.status_code == 404
    assert "max-age" in resp.headers["cache-control"]


async def test_unknown_package_page_never_touches_pypi(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    resp = await client.get("/package/whatever/1.0")
    assert resp.status_code == 404
    assert fake_pypi.requests == []
    assert jobs.depth(db.connect(settings.database_path)) == {}


async def test_queued_package_page_is_503(client: httpx.AsyncClient) -> None:
    jobs.enqueue(db.connect(settings.database_path), "later", "1.0", jobs.PRIORITY_BACKFILL)
    resp = await client.get("/package/later/1.0")
    assert resp.status_code == 503
    assert resp.headers["retry-after"]


async def test_listing_pagination_and_format_filter(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pages, "PAGE_SIZE", 2)
    await _seed(fake_pypi, ("a", "1", True), ("b", "1", True), ("c", "1", True), ("d", "1", False))
    page1 = await client.get("/packages")
    page2 = await client.get("/packages?page=2")
    assert page1.status_code == 200 and page2.status_code == 200
    assert "/package/a/1" in page1.text and "/package/b/1" in page1.text
    assert "/package/c/1" in page2.text
    assert "/package/d/1" not in page1.text + page2.text
    assert (await client.get("/packages?page=3")).status_code == 404
    assert (await client.get("/packages?format=CycloneDX")).status_code == 200
    assert (await client.get("/packages?format=Bogus")).status_code == 404


async def test_sitemap_index_and_shards(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(seo, "SHARD_SIZE", 2)
    await _seed(fake_pypi, ("a", "1", True), ("b", "1", True), ("c", "1", True))
    index = ElementTree.fromstring((await client.get("/sitemap.xml")).text)
    locs = [e.text for e in index.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
    assert locs[-2:] == [f"{settings.server_root_url}/sitemap-0.xml", f"{settings.server_root_url}/sitemap-1.xml"]
    shard1 = (await client.get("/sitemap-1.xml")).text
    assert "/package/c/1" in shard1 and "/package/a/1" not in shard1
    assert (await client.get("/sitemap-5.xml")).status_code == 404


async def test_robots_keeps_crawlers_off_the_api(client: httpx.AsyncClient) -> None:
    text = (await client.get("/robots.txt")).text
    assert "Allow: /package/" in text
    for path in ("/artifact/", "/discovery", "/product"):
        assert f"Disallow: {path}" in text
    assert f"Sitemap: {settings.server_root_url}/sitemap.xml" in text


async def test_stats(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, ("a", "1", True), ("b", "1", False))
    data = (await client.get("/stats")).json()
    assert data["packages"]["total_explored"] == 2
    assert data["packages"]["with_sbom"] == 1
    assert data["wheels"] == {"total_checked": 2, "with_sbom": 1, "without_sbom": 1, "sbom_percentage": 50.0}
    assert data["sbom_formats"] == {"CycloneDX/1.6": 1}
    assert data["attestations"] == {"not_available": 2}
    assert (await client.get("/stats/timeseries")).status_code == 200
    assert (await client.get("/stats/usage")).status_code == 200
    assert (await client.get("/stats/invalid-sboms")).json() == []


async def test_healthz(client: httpx.AsyncClient) -> None:
    assert (await client.get("/healthz")).json() == {"status": "ok"}


# --- read-path backpressure ---


async def test_unknown_release_is_queued_and_pending(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "resolve_wait_seconds", 0.3)
    resp = await client.get("/discovery", params={"tei": "urn:tei:purl:x:pkg:pypi/newpkg@1.0"})
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "5"
    assert resp.headers["cache-control"] == "no-store"
    assert jobs.depth(db.connect(settings.database_path)) == {jobs.PRIORITY_INTERACTIVE: 1}


async def test_lookups_are_shed_when_queue_is_full(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "max_pending_lookups", 2)
    monkeypatch.setattr(lookup._gate, "_depth_at", 0.0)
    conn = db.connect(settings.database_path)
    jobs.enqueue(conn, "x", "1", jobs.PRIORITY_INTERACTIVE)
    jobs.enqueue(conn, "y", "1", jobs.PRIORITY_INTERACTIVE)
    resp = await client.get("/discovery", params={"tei": "urn:tei:purl:x:pkg:pypi/z@1"})
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "30"
    assert not jobs.is_queued(conn, "z", "1")


async def test_lookup_returns_once_worker_resolves(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "resolve_wait_seconds", 5.0)
    fake_pypi.add("late", "1.0", [("late-1.0-py3-none-any.whl", sbom_wheel("late", "1.0"))])

    async def fake_worker() -> None:
        conn = db.connect(settings.database_path)
        while not jobs.is_queued(conn, "late", "1.0"):
            await asyncio.sleep(0.05)
        async with fake_pypi.client() as c:
            await ingest_release(c, "late", "1.0")

    worker = asyncio.create_task(fake_worker())
    resp = await client.get("/discovery", params={"tei": "urn:tei:purl:x:pkg:pypi/late@1.0"})
    await worker
    assert resp.status_code == 200
    assert resp.json()[0]["productReleaseUuid"]


async def test_release_pypi_does_not_have_is_404(client: httpx.AsyncClient) -> None:
    store.mark_missing(db.connect(settings.database_path), "ghost", "1.0")
    resp = await client.get("/discovery", params={"tei": "urn:tei:purl:x:pkg:pypi/ghost@1.0"})
    assert resp.status_code == 404


async def test_non_canonical_package_url_redirects(client: httpx.AsyncClient) -> None:
    resp = await client.get("/package/Ruamel.YAML/0.18.6")
    assert resp.status_code == 301
    assert resp.headers["location"] == "/package/ruamel-yaml/0.18.6"


async def test_products_list_comes_from_listing(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, ("a", "1", True), ("b", "1", False), ("b", "2", False))
    products = (await client.get("/products", params={"pageOffset": 1, "pageSize": 1})).json()
    assert products["totalResults"] == 2
    assert [p["name"] for p in products["results"]] == ["b"]
    releases = (await client.get("/productReleases", params={"pageOffset": 0, "pageSize": 10})).json()
    assert releases["totalResults"] == 3


async def test_out_of_range_sitemap_shard_is_not_memoized(client: httpx.AsyncClient) -> None:
    before = len(lookup._memo)
    for n in range(5, 50):
        assert (await client.get(f"/sitemap-{n}.xml")).status_code == 404
    assert len(lookup._memo) <= before + 1


async def test_memoized_single_flight(database: str) -> None:
    calls = 0

    def slow(_conn: object) -> int:
        nonlocal calls
        calls += 1
        import time

        time.sleep(0.1)
        return 42

    results = await asyncio.gather(*(lookup.memoized("sf-test", 60.0, slow) for _ in range(10)))
    assert results == [42] * 10
    assert calls == 1


async def test_package_markdown_and_json(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, ("maturin", "1.8.1", True))
    page = await client.get("/package/maturin/1.8.1")
    assert '<link rel="alternate" type="text/markdown" href="/package/maturin/1.8.1.md"' in page.text
    assert "Copy as Markdown" in page.text and "/static/js/page-tools.js" in page.text

    canonical = f"{settings.server_root_url}/package/maturin/1.8.1"
    resp = await client.get("/package/maturin/1.8.1.md")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    assert resp.headers["x-robots-tag"] == "noindex"
    assert resp.headers["link"] == f'<{canonical}>; rel="canonical"'
    assert "s-maxage" in resp.headers["cache-control"]
    assert resp.text.startswith("# SBOM for maturin 1.8.1\n")
    assert "`pkg:pypi/maturin@1.8.1`" in resp.text
    assert f"]({settings.server_root_url}/artifact/" in resp.text
    assert "\n\n\n" not in resp.text

    data = (await client.get("/package/maturin/1.8.1.json")).json()
    assert data["url"] == canonical and data["purl"] == "pkg:pypi/maturin@1.8.1"
    assert data["formats"] == ["CycloneDX"]
    assert data["wheels"][0]["sboms"][0]["download_url"].startswith(f"{settings.server_root_url}/artifact/")


async def test_package_twins_redirect_and_404(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, ("plain", "1.0", False))
    resp = await client.get("/package/Ruamel.YAML/0.18.md", follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers["location"] == "/package/ruamel-yaml/0.18.md"
    assert (await client.get("/package/plain/1.0.md")).status_code == 404
    assert (await client.get("/package/whatever/1.0.json")).status_code == 404
    jobs.enqueue(db.connect(settings.database_path), "later", "1.0", jobs.PRIORITY_BACKFILL)
    assert (await client.get("/package/later/1.0.md")).status_code == 503


async def test_listing_markdown(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pages, "PAGE_SIZE", 2)
    await _seed(fake_pypi, ("a", "1", True), ("b", "1", True), ("c", "1", True))
    html = (await client.get("/packages?page=2")).text
    assert 'type="text/markdown" href="/packages.md?page=2"' in html
    page1 = await client.get("/packages.md")
    assert page1.status_code == 200
    assert page1.text.startswith("# PyPI packages with SBOMs\n\n3 Python packages")
    assert page1.headers["x-robots-tag"] == "noindex"
    assert f"({settings.server_root_url}/package/a/1)" in page1.text
    assert f"Next page: {settings.server_root_url}/packages.md?page=2" in page1.text
    page2 = (await client.get("/packages.md?format=CycloneDX&page=2")).text
    assert "/package/c/1" in page2 and "/package/a/1" not in page2
    assert f"Previous page: {settings.server_root_url}/packages.md?format=CycloneDX\n" in page2
    assert (await client.get("/packages.md?page=9")).status_code == 404
    assert (await client.get("/packages.md?format=Bogus")).status_code == 404


async def test_dashboard_markdown_and_llms_txt(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, ("a", "1", True), ("b", "1", False))
    assert 'type="text/markdown" href="/index.md"' in (await client.get("/")).text
    home = await client.get("/index.md")
    assert home.status_code == 200
    assert home.headers["link"] == f'<{settings.server_root_url}/>; rel="canonical"'
    assert "- Package versions explored: 2" in home.text
    assert "CycloneDX/1.6 (1)" in home.text
    llms = await client.get("/llms.txt")
    assert llms.status_code == 200 and llms.headers["content-type"].startswith("text/plain")
    assert llms.text.startswith("# pypi-tea\n")
    assert f"{settings.server_root_url}/packages.md" in llms.text


def test_markdown_escapes_third_party_text() -> None:
    assert pages.md("[click](http://evil) <b>*hi*</b>\n# x") == r"\[click\](http://evil) \<b\>\*hi\*\</b\> \# x"
    assert pages.md("x" * 20, limit=10) == "x" * 9 + "…"
    assert pages.md_url("https://example.com/a b)") == "https://example.com/a%20b%29"

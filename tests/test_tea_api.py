"""TEA 1.0.0 behaviour the libtea conformance suite does not check: paging, sorting, discovery forms,
error bodies, response shapes and artifact downloads. Offline, against a fake PyPI."""

import base64
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from libtea.discovery import purl_tei

from conftest import FakePyPI, sbom_wheel
from pypi_tea import db
from pypi_tea.app import app
from pypi_tea.config import TEA_VERSION, settings
from pypi_tea.ingest import ingest_release
from pypi_tea.services.uuids import product_uuid

pytestmark = pytest.mark.anyio
V = f"/v{TEA_VERSION}"


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
async def client(database: str, fake_pypi: FakePyPI) -> AsyncIterator[httpx.AsyncClient]:
    """Three products, stored in the order b, a, c; b has two releases and a two wheels."""
    fake_pypi.add("b", "1.0", [("b-1.0-py3-none-any.whl", sbom_wheel("b", "1.0"))])
    fake_pypi.add(
        "a",
        "2.0",
        [(f"a-2.0-{tag}.whl", sbom_wheel("a", "2.0")) for tag in ("py3-none-any", "cp313-abi3-linux_x86_64")],
    )
    fake_pypi.add("c", "0.1", [("c-0.1-py3-none-any.whl", sbom_wheel("c", "0.1"))])
    fake_pypi.add("b", "1.1", [("b-1.1-py3-none-any.whl", sbom_wheel("b", "1.1"))])
    async with fake_pypi.client() as pypi:
        for name, version in (("b", "1.0"), ("a", "2.0"), ("c", "0.1"), ("b", "1.1")):
            await ingest_release(pypi, name, version)
    conn = db.connect(database)
    # Stored a second apart, so createdDate orders them; b@1.1 before b@1.0 by upload time.
    for i, (name, version) in enumerate((("b", "1.0"), ("a", "2.0"), ("c", "0.1"), ("b", "1.1"))):
        conn.execute(
            "UPDATE releases SET first_seen = ? WHERE name = ? AND version = ?", (1_700_000_000 + i, name, version)
        )
    conn.execute("UPDATE releases SET created = '2024-01-01T00:00:00Z' WHERE name = 'b' AND version = '1.1'")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _pages(client: httpx.AsyncClient, path: str, **params: Any) -> list[dict[str, Any]]:
    """Every page of a list, following nextPageToken."""
    pages = []
    query = dict(params)
    while True:
        resp = await client.get(path, params=query)
        assert resp.status_code == 200, resp.text
        page = resp.json()
        pages.append(page)
        if not page["hasNext"]:
            assert "nextPageToken" not in page
            return pages
        query = {**params, "pageToken": page["nextPageToken"]}


def _results(pages: list[dict[str, Any]], key: str = "name") -> list[Any]:
    return [r[key] for page in pages for r in page["results"]]


def _no_nulls(value: Any) -> None:
    assert value is not None
    for child in value.values() if isinstance(value, dict) else value if isinstance(value, list) else ():
        _no_nulls(child)


# --- paging and sorting ---


async def test_products_page_by_name(client: httpx.AsyncClient) -> None:
    pages = await _pages(client, f"{V}/products", pageSize=1)
    assert _results(pages) == ["a", "b", "c"]
    assert [len(p["results"]) for p in pages] == [1, 1, 1]
    assert "totalResults" not in pages[0] and "pageStartIndex" not in pages[0]
    desc = await _pages(client, f"{V}/products", pageSize=2, sortOrder="desc")
    assert _results(desc) == ["c", "b", "a"]


async def test_page_size_defaults_to_25_and_stops_at_100(client: httpx.AsyncClient) -> None:
    assert len((await client.get(f"{V}/products")).json()["results"]) == 3
    for size in (0, 101):
        resp = await client.get(f"{V}/products", params={"pageSize": size})
        assert resp.status_code == 400
        assert resp.json()["error"] == "INVALID_REQUEST"


async def test_page_token_is_bound_to_its_query(client: httpx.AsyncClient) -> None:
    token = (await client.get(f"{V}/products", params={"pageSize": 1})).json()["nextPageToken"]
    for path, params in (
        (f"{V}/products", {"sortOrder": "desc"}),  # another sort order
        ("/products", {}),  # another path: the unversioned mount
        (f"{V}/productReleases", {}),
    ):
        resp = await client.get(path, params={**params, "pageToken": token})
        assert resp.status_code == 400, path
        assert resp.json()["error"] == "INVALID_PAGE_TOKEN"
    forged = base64.urlsafe_b64encode(json.dumps({"q": [f"{V}/products"], "c": [-1]}).encode()).decode()
    for bad in ("not-a-token", forged, ""):
        resp = await client.get(f"{V}/products", params={"pageToken": bad})
        assert resp.status_code == 400, bad
        assert resp.json()["error"] == "INVALID_PAGE_TOKEN"


async def test_catalog_releases_by_created_date(client: httpx.AsyncClient) -> None:
    pages = await _pages(client, f"{V}/productReleases", pageSize=3)
    assert _results(pages, "version") == ["1.0", "2.0", "0.1", "1.1"]
    desc = await _pages(client, f"{V}/productReleases", pageSize=3, sortOrder="desc")
    assert _results(desc, "version") == ["1.1", "0.1", "2.0", "1.0"]
    resp = await client.get(f"{V}/productReleases", params={"sortField": "version"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "INVALID_REQUEST"


async def test_product_releases_sort_fields(client: httpx.AsyncClient) -> None:
    path = f"{V}/product/{product_uuid('b')}/releases"
    assert _results(await _pages(client, path, pageSize=1), "version") == ["1.0", "1.1"]
    assert _results(await _pages(client, path, sortField="releaseDate"), "version") == ["1.1", "1.0"]
    assert _results(await _pages(client, path, sortField="version", sortOrder="desc"), "version") == ["1.1", "1.0"]
    release = (await client.get(path)).json()["results"][0]
    assert release["createdDate"] == "2023-11-14T22:13:20Z"
    assert release["releaseDate"] == "2025-01-02T03:04:05Z"


async def test_components_and_their_releases(client: httpx.AsyncClient) -> None:
    pages = await _pages(client, f"{V}/components", pageSize=2)
    names = _results(pages)
    assert names == sorted(names) and len(names) == 5
    assert _results(await _pages(client, f"{V}/components", sortOrder="desc")) == names[::-1]
    # Releases in createdDate order, each split across pages as needed: a@2.0's two wheels share a page boundary.
    releases = await _pages(client, f"{V}/componentReleases", pageSize=1)
    assert [r["componentName"].split("-")[1] for p in releases for r in p["results"]] == [
        "1.0",
        "2.0",
        "2.0",
        "0.1",
        "1.1",
    ]

    wheel_purl = "pkg:pypi/a@2.0?file_name=a-2.0-py3-none-any.whl"
    found = (await client.get(f"{V}/components", params={"idType": "PURL", "idValue": wheel_purl})).json()["results"]
    assert [c["identifiers"] for c in found] == [[{"idType": "PURL", "idValue": wheel_purl}]]
    found = await client.get(f"{V}/componentReleases", params={"idType": "PURL", "idValue": "pkg:pypi/a@2.0"})
    assert len(found.json()["results"]) == 2
    found = await client.get(f"{V}/components", params={"idType": "CPE", "idValue": "cpe:2.3:a:x:a:2.0"})
    assert found.json() == {"hasNext": False, "results": []}


# --- discovery ---


async def test_discovery_forms(client: httpx.AsyncClient) -> None:
    purl = "pkg:pypi/a@2.0"
    for params in (
        {"tei": purl_tei("pypi.example.com", purl)},
        {"tei": f"urn:tei:purl:pypi.example.com:{purl}"},
        {"purl": purl},
    ):
        resp = await client.get(f"{V}/discovery", params=params)
        assert resp.status_code == 200, params
        [found] = resp.json()
        assert found["servers"] == [{"rootUrl": settings.server_root_url, "versions": ["1.0.0"]}]


async def test_discovery_errors(client: httpx.AsyncClient) -> None:
    for params in ({}, {"tei": purl_tei("x.example.com", "pkg:pypi/a@2.0"), "purl": "pkg:pypi/a@2.0"}, {"tei": "nope"}):
        resp = await client.get(f"{V}/discovery", params=params)
        assert resp.status_code == 400, params
        assert resp.json()["error"] == "INVALID_REQUEST"
    for params in (
        {"tei": "tei://x.example.com/uuid/00000000-0000-0000-0000-000000000000"},
        {"purl": "pkg:npm/left-pad@1.0.0"},
    ):
        resp = await client.get(f"{V}/discovery", params=params)
        assert resp.status_code == 404, params
        assert resp.json() == {"error": "OBJECT_UNKNOWN"}


# --- shapes ---


async def test_release_shapes(client: httpx.AsyncClient) -> None:
    [found] = (await client.get(f"{V}/discovery", params={"purl": "pkg:pypi/a@2.0"})).json()
    release = (await client.get(f"{V}/productRelease/{found['productReleaseUuid']}")).json()
    _no_nulls(release)
    collection = release["latestCollection"]
    assert collection["createdDate"] == release["createdDate"] and "date" not in collection
    assert collection["version"] == 1 and collection["belongsTo"] == "PRODUCT_RELEASE"
    assert {a["version"] for a in collection["artifacts"]} == {1}

    component_release = (await client.get(f"{V}/componentRelease/{release['components'][0]['release']}")).json()
    _no_nulls(component_release)
    assert "release" not in component_release  # flat, as TEA 1.0.0 defines it
    assert component_release["latestCollection"]["belongsTo"] == "COMPONENT_RELEASE"
    [distribution] = component_release["distributions"]
    assert {c["algType"] for c in distribution["checksums"]} == {"SHA-256"}  # never MD5
    assert distribution["distributionId"] != component_release["uuid"]


async def test_cle_is_not_implemented(client: httpx.AsyncClient) -> None:
    resp = await client.get(f"{V}/product/{product_uuid('a')}/cle")
    assert resp.status_code == 404
    assert resp.json() == {"error": "NOT_IMPLEMENTED"}
    resp = await client.get(f"{V}/product/00000000-0000-0000-0000-000000000000/cle")
    assert resp.json() == {"error": "OBJECT_UNKNOWN"}


# --- artifacts ---


async def _artifact(client: httpx.AsyncClient) -> dict[str, Any]:
    [found] = (await client.get(f"{V}/discovery", params={"purl": "pkg:pypi/c@0.1"})).json()
    collection = (await client.get(f"{V}/productRelease/{found['productReleaseUuid']}/collection/latest")).json()
    return dict(collection["artifacts"][0])


async def test_artifact_revisions(client: httpx.AsyncClient) -> None:
    artifact = await _artifact(client)
    uuid = artifact["uuid"]
    for path in (f"{V}/artifact/{uuid}/latest", f"{V}/artifact/{uuid}/1"):
        assert (await client.get(path)).json() == artifact
    assert (await client.get(f"{V}/artifact/{uuid}/2")).status_code == 404
    assert (await client.get(f"{V}/artifact/{uuid}")).status_code == 404  # the 0.x path


async def test_artifact_download(client: httpx.AsyncClient) -> None:
    artifact = await _artifact(client)
    uuid, media_type = artifact["uuid"], artifact["formats"][0]["mediaType"]
    sha256 = artifact["formats"][0]["checksums"][0]["algValue"]
    location = f"{settings.server_root_url}{V}/artifact/{uuid}/1/download?mediaType=application%2Fvnd.cyclonedx%2Bjson"

    latest = await client.get(f"{V}/artifact/{uuid}/latest/download")
    assert latest.status_code == 200
    assert latest.headers["etag"] == f'"{sha256}"'
    assert latest.headers["content-location"] == location
    assert latest.headers["cache-control"] == "public, no-cache"
    versioned = await client.get(f"{V}/artifact/{uuid}/1/download", params={"mediaType": media_type.upper()})
    assert versioned.content == latest.content
    assert "immutable" not in versioned.headers["cache-control"] and "max-age" in versioned.headers["cache-control"]

    unchanged = await client.get(f"{V}/artifact/{uuid}/latest/download", headers={"If-None-Match": f'W/"{sha256}"'})
    assert unchanged.status_code == 304
    assert unchanged.headers["etag"] == f'"{sha256}"' and unchanged.headers["content-location"] == location

    resp = await client.get(f"{V}/artifact/{uuid}/1/download", params={"mediaType": "application/spdx+json"})
    assert resp.status_code == 406
    assert resp.json()["error"] == "NO_ACCEPTABLE_FORMAT"
    resp = await client.get(f"{V}/artifact/{uuid}/latest/signature/download")
    assert resp.status_code == 404
    assert resp.json() == {"error": "SIGNATURE_NOT_FOUND"}
    resp = await client.get(f"{V}/artifact/{uuid}/2/signature/download")
    assert resp.json() == {"error": "OBJECT_UNKNOWN"}

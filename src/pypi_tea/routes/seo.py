"""robots.txt and a sharded sitemap.

Crawlers are pointed at the HTML pages and kept off the API: the API is for
TEA clients, and an unknown PURL there costs a PyPI round trip.

Each package page stays in the shard it was first put in (see `store.sitemap`),
so a catalog change rewrites one shard and moves that shard's `lastmod` in the
index; crawlers can skip the rest.
"""

import gzip
import sqlite3
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape

from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse

from pypi_tea import store
from pypi_tea.config import settings
from pypi_tea.lookup import memoized

router = APIRouter()

_SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
INDEX_TTL = 60.0
SHARD_TTL = 600.0
SITEMAP_CACHE = "public, max-age=3600, s-maxage=3600, stale-if-error=86400"
# lastmod of the home and listing pages while the catalog is still empty.
_STARTED = int(time.time())

_DISALLOW = (
    "/artifact/",
    "/attestation/",
    "/component",
    "/discovery",
    "/product",
    "/stats",
    "/v",
)


@dataclass(frozen=True)
class _Document:
    """An XML document and its gzip encoding, built once per memoized render."""

    body: bytes
    gzipped: bytes

    @classmethod
    def of(cls, lines: list[str]) -> _Document:
        body = "\n".join(lines).encode()
        return cls(body, gzip.compress(body, compresslevel=6, mtime=0))


@dataclass(frozen=True)
class _Catalog:
    shards: dict[int, int]  # shard -> lastmod
    index: _Document
    pages: _Document


def _w3c(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _url(loc: str, lastmod: int) -> str:
    return f"<url><loc>{escape(loc)}</loc><lastmod>{_w3c(lastmod)}</lastmod></url>"


def _sitemap(loc: str, lastmod: int) -> str:
    return f"<sitemap><loc>{escape(loc)}</loc><lastmod>{_w3c(lastmod)}</lastmod></sitemap>"


def _accepts_gzip(accept_encoding: str) -> bool:
    for part in accept_encoding.split(","):
        coding, _, params = part.partition(";")
        if coding.strip().lower() not in ("gzip", "*"):
            continue
        q = params.strip().lower()
        if q.startswith("q="):
            try:
                return float(q[2:]) > 0
            except ValueError:
                return False
        return True
    return False


def _respond(request: Request, doc: _Document) -> Response:
    headers = {"Cache-Control": SITEMAP_CACHE, "Vary": "Accept-Encoding"}
    if _accepts_gzip(request.headers.get("accept-encoding", "")):
        headers["Content-Encoding"] = "gzip"
        return Response(doc.gzipped, media_type="application/xml", headers=headers)
    return Response(doc.body, media_type="application/xml", headers=headers)


def _render_catalog(conn: sqlite3.Connection) -> _Catalog:
    root = settings.server_root_url.rstrip("/")
    shards = dict(store.sitemap_shards(conn))
    # The home page and the listing show the catalog, so they change when any shard does.
    newest = max(shards.values(), default=_STARTED)
    index = ['<?xml version="1.0" encoding="UTF-8"?>', f'<sitemapindex xmlns="{_SITEMAP_NS}">']
    index.append(_sitemap(f"{root}/sitemap-pages.xml", newest))
    index.extend(_sitemap(f"{root}/sitemap-{shard}.xml", lastmod) for shard, lastmod in shards.items())
    index.append("</sitemapindex>")
    pages = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<urlset xmlns="{_SITEMAP_NS}">',
        _url(f"{root}/", newest),
        _url(f"{root}/packages", newest),
        "</urlset>",
    ]
    return _Catalog(shards, _Document.of(index), _Document.of(pages))


def _render_shard(conn: sqlite3.Connection, shard: int) -> _Document:
    root = settings.server_root_url.rstrip("/")
    body = ['<?xml version="1.0" encoding="UTF-8"?>', f'<urlset xmlns="{_SITEMAP_NS}">']
    body.extend(_url(f"{root}/package/{n}/{v}", lastmod) for n, v, lastmod in store.sitemap_shard(conn, shard))
    body.append("</urlset>")
    return _Document.of(body)


@router.get("/sitemap.xml")
async def sitemap_index(request: Request) -> Response:
    catalog = await memoized("sitemap:catalog", INDEX_TTL, _render_catalog)
    return _respond(request, catalog.index)


@router.get("/sitemap-pages.xml")
async def sitemap_pages(request: Request) -> Response:
    catalog = await memoized("sitemap:catalog", INDEX_TTL, _render_catalog)
    return _respond(request, catalog.pages)


@router.get("/sitemap-{shard:int}.xml")
async def sitemap_shard(request: Request, shard: int) -> Response:
    catalog = await memoized("sitemap:catalog", INDEX_TTL, _render_catalog)
    if shard not in catalog.shards:
        return Response(status_code=404)
    # A shard is ~1 MB of XML; build and compress it at most once per SHARD_TTL per process.
    doc = await memoized(f"sitemap:{shard}", SHARD_TTL, _render_shard, shard)
    return _respond(request, doc)


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> str:
    root = settings.server_root_url.rstrip("/")
    lines = ["User-agent: *", "Allow: /$", "Allow: /package/", "Allow: /packages"]
    lines += [f"Disallow: {p}" for p in _DISALLOW]
    lines += ["", f"Sitemap: {root}/sitemap.xml", ""]
    return "\n".join(lines)

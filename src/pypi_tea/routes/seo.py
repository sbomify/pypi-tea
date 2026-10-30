"""robots.txt and a sharded sitemap.

Crawlers are pointed at the HTML pages and kept off the API: the API is for
TEA clients, and an unknown PURL there costs a PyPI round trip.
"""

import math
import sqlite3
from html import escape

from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse

from pypi_tea import store
from pypi_tea.config import settings
from pypi_tea.lookup import memoized

router = APIRouter()

_SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
# Google accepts up to 50k URLs per sitemap; stay well under so each shard is a cheap range read.
SHARD_SIZE = 10_000
SHARD_TTL = 600.0
SITEMAP_CACHE = "public, max-age=3600, s-maxage=3600, stale-if-error=86400"

_DISALLOW = (
    "/artifact/",
    "/attestation/",
    "/component",
    "/discovery",
    "/product",
    "/stats",
    "/v",
)


def _url(loc: str, priority: str, changefreq: str) -> str:
    return f"<url><loc>{escape(loc)}</loc><priority>{priority}</priority><changefreq>{changefreq}</changefreq></url>"


@router.get("/sitemap.xml")
async def sitemap_index() -> Response:
    root = settings.server_root_url.rstrip("/")
    total = await memoized("count:None", 60.0, store.count_packages_with_sbom, None)
    shards = max(1, math.ceil(total / SHARD_SIZE))
    body = ['<?xml version="1.0" encoding="UTF-8"?>', f'<sitemapindex xmlns="{_SITEMAP_NS}">']
    body.append(f"<sitemap><loc>{escape(root)}/sitemap-pages.xml</loc></sitemap>")
    body.extend(f"<sitemap><loc>{escape(root)}/sitemap-{i}.xml</loc></sitemap>" for i in range(shards))
    body.append("</sitemapindex>")
    return Response("\n".join(body), media_type="application/xml", headers={"Cache-Control": SITEMAP_CACHE})


@router.get("/sitemap-pages.xml")
async def sitemap_pages() -> Response:
    root = settings.server_root_url.rstrip("/")
    body = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<urlset xmlns="{_SITEMAP_NS}">',
        _url(f"{root}/", "1.0", "daily"),
        _url(f"{root}/packages", "0.8", "daily"),
        "</urlset>",
    ]
    return Response("\n".join(body), media_type="application/xml", headers={"Cache-Control": SITEMAP_CACHE})


def _render_shard(conn: sqlite3.Connection, shard: int) -> str | None:
    rows = store.packages_with_sbom(conn, None, shard * SHARD_SIZE, SHARD_SIZE)
    if not rows and shard > 0:
        return None
    root = settings.server_root_url.rstrip("/")
    body = ['<?xml version="1.0" encoding="UTF-8"?>', f'<urlset xmlns="{_SITEMAP_NS}">']
    body.extend(_url(f"{root}/package/{n}/{v}", "0.6", "weekly") for n, v, _ in rows)
    body.append("</urlset>")
    return "\n".join(body)


@router.get("/sitemap-{shard:int}.xml")
async def sitemap_shard(shard: int) -> Response:
    # A shard is ~1 MB of XML; build it at most once per SHARD_TTL per process.
    body = await memoized(f"sitemap:{shard}", SHARD_TTL, _render_shard, shard)
    if body is None:
        return Response(status_code=404)
    return Response(body, media_type="application/xml", headers={"Cache-Control": SITEMAP_CACHE})


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> str:
    root = settings.server_root_url.rstrip("/")
    lines = ["User-agent: *", "Allow: /$", "Allow: /package/", "Allow: /packages"]
    lines += [f"Disallow: {p}" for p in _DISALLOW]
    lines += ["", f"Sitemap: {root}/sitemap.xml", ""]
    return "\n".join(lines)

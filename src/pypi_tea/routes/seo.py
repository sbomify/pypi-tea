from html import escape

from fastapi import APIRouter, Depends, Response
from fastapi.responses import PlainTextResponse

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.deps import get_cache

router = APIRouter()

_SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"


def _url_entry(loc: str, priority: str, changefreq: str) -> str:
    return f"<url><loc>{escape(loc)}</loc><priority>{priority}</priority><changefreq>{changefreq}</changefreq></url>"


@router.get("/sitemap.xml")
async def sitemap(cache: Cache = Depends(get_cache)) -> Response:
    items, _total = await cache.get_packages_with_sbom()
    root_url = settings.server_root_url.rstrip("/")

    # Build XML incrementally as a list of strings to avoid ElementTree overhead
    parts: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<urlset xmlns="{_SITEMAP_NS}">',
    ]

    # Static pages
    parts.append(_url_entry(f"{root_url}/", "1.0", "daily"))
    parts.append(_url_entry(f"{root_url}/packages", "0.8", "daily"))

    # Package pages
    for item in items:
        split = item.rsplit("@", 1)
        if len(split) != 2:
            continue
        name, version = split
        parts.append(_url_entry(f"{root_url}/package/{name}/{version}", "0.6", "weekly"))

    parts.append("</urlset>")
    xml_str = "\n".join(parts)

    return Response(
        content=xml_str,
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=3600, s-maxage=3600"},
    )


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> str:
    root_url = settings.server_root_url.rstrip("/")
    return f"User-agent: *\nAllow: /\n\nSitemap: {root_url}/sitemap.xml\n"

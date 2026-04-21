from collections.abc import AsyncIterator
from html import escape

from fastapi import APIRouter, Depends, Response
from fastapi.responses import PlainTextResponse
from starlette.responses import StreamingResponse

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.deps import get_cache

router = APIRouter()

_SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"


def _url_entry(loc: str, priority: str, changefreq: str) -> str:
    return f"<url><loc>{escape(loc)}</loc><priority>{priority}</priority><changefreq>{changefreq}</changefreq></url>"


async def _sitemap_xml(cache: Cache) -> AsyncIterator[str]:
    """Stream sitemap XML using cursor-based SSCAN to avoid loading the full set."""
    root_url = settings.server_root_url.rstrip("/")
    yield '<?xml version="1.0" encoding="UTF-8"?>\n'
    yield f'<urlset xmlns="{_SITEMAP_NS}">\n'
    yield _url_entry(f"{root_url}/", "1.0", "daily") + "\n"
    yield _url_entry(f"{root_url}/packages", "0.8", "daily") + "\n"
    async for item in cache.scan_packages_with_sbom():
        split = item.rsplit("@", 1)
        if len(split) != 2:
            continue
        name, version = split
        yield _url_entry(f"{root_url}/package/{name}/{version}", "0.6", "weekly") + "\n"
    yield "</urlset>\n"


@router.get("/sitemap.xml")
async def sitemap(cache: Cache = Depends(get_cache)) -> Response:
    return StreamingResponse(
        _sitemap_xml(cache),
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=3600, s-maxage=3600"},
    )


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> str:
    root_url = settings.server_root_url.rstrip("/")
    return f"User-agent: *\nAllow: /\n\nSitemap: {root_url}/sitemap.xml\n"

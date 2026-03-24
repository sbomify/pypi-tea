import xml.etree.ElementTree as ET

from fastapi import APIRouter, Depends, Response
from fastapi.responses import PlainTextResponse

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.deps import get_cache

router = APIRouter()

_SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"


@router.get("/sitemap.xml")
async def sitemap(cache: Cache = Depends(get_cache)) -> Response:
    items, _total = await cache.get_packages_with_sbom()
    root_url = settings.server_root_url.rstrip("/")

    urlset = ET.Element("urlset", xmlns=_SITEMAP_NS)

    # Static pages
    for path, priority in [("/", "1.0"), ("/packages", "0.8")]:
        url_el = ET.SubElement(urlset, "url")
        ET.SubElement(url_el, "loc").text = f"{root_url}{path}"
        ET.SubElement(url_el, "priority").text = priority
        ET.SubElement(url_el, "changefreq").text = "daily"

    # Package pages
    for item in items:
        parts = item.rsplit("@", 1)
        if len(parts) != 2:
            continue
        name, version = parts
        url_el = ET.SubElement(urlset, "url")
        ET.SubElement(url_el, "loc").text = f"{root_url}/package/{name}/{version}"
        ET.SubElement(url_el, "priority").text = "0.6"
        ET.SubElement(url_el, "changefreq").text = "weekly"

    xml_bytes = ET.tostring(urlset, encoding="unicode", xml_declaration=False)
    xml_str = f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_bytes}'

    return Response(
        content=xml_str,
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=3600, s-maxage=3600"},
    )


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> str:
    root_url = settings.server_root_url.rstrip("/")
    return f"User-agent: *\nAllow: /\n\nSitemap: {root_url}/sitemap.xml\n"

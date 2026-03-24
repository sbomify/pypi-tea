import math
from importlib.metadata import version
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.deps import get_cache

router = APIRouter()

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_jinja_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)

PAGE_SIZE = 50


def _render(template_name: str, **ctx: Any) -> str:
    ctx.setdefault("version", version("pypi-tea"))
    ctx.setdefault("server_root_url", settings.server_root_url)
    template = _jinja_env.get_template(template_name)
    return template.render(**ctx)


@router.get("/package/{name}/{pkg_version}", response_class=HTMLResponse)
async def package_page(
    name: str,
    pkg_version: str,
    cache: Cache = Depends(get_cache),
) -> HTMLResponse:
    data = await cache.get_package_page_data(name, pkg_version)
    if data is None:
        html = _render("404.html")
        return HTMLResponse(content=html, status_code=404)

    canonical_url = f"{settings.server_root_url}/package/{name}/{pkg_version}"
    html = _render("package.html", **data, canonical_url=canonical_url)
    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "public, max-age=3600, s-maxage=3600"},
    )


@router.get("/packages", response_class=HTMLResponse)
async def packages_listing(
    page: int = Query(1, ge=1),
    format: str | None = Query(None),
    cache: Cache = Depends(get_cache),
) -> HTMLResponse:
    offset = (page - 1) * PAGE_SIZE
    active_format = format

    if active_format:
        items, total = await cache.get_packages_with_sbom_by_format(active_format, offset, PAGE_SIZE)
    else:
        items, total = await cache.get_packages_with_sbom(offset, PAGE_SIZE)

    # Parse package@version strings and enrich with format info
    packages: list[dict[str, Any]] = []
    for item in items:
        parts = item.rsplit("@", 1)
        if len(parts) != 2:
            continue
        pkg_name, pkg_version = parts
        formats = await cache.get_package_formats(pkg_name, pkg_version)
        packages.append({"name": pkg_name, "version": pkg_version, "formats": formats})

    total_pages = max(1, math.ceil(total / PAGE_SIZE))

    canonical_parts = [f"{settings.server_root_url}/packages"]
    query_parts: list[str] = []
    if active_format:
        query_parts.append(f"format={active_format}")
    if page > 1:
        query_parts.append(f"page={page}")
    canonical_url = canonical_parts[0] + ("?" + "&".join(query_parts) if query_parts else "")

    html = _render(
        "packages.html",
        packages=packages,
        total=total,
        page=page,
        total_pages=total_pages,
        active_format=active_format,
        canonical_url=canonical_url,
    )
    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "public, max-age=300, s-maxage=300"},
    )

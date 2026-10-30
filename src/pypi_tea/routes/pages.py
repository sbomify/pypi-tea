"""Server-rendered HTML pages for search engines and humans. Store reads only."""

import math
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from pypi_tea import jobs, store
from pypi_tea.config import settings
from pypi_tea.lookup import memoized, read
from pypi_tea.models import ReleaseRecord

router = APIRouter()

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_jinja_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
_VERSION = pkg_version("pypi-tea")

PAGE_SIZE = 50
COUNT_TTL = 60.0

PAGE_CACHE = "public, max-age=3600, s-maxage=86400, stale-while-revalidate=86400, stale-if-error=604800"
LIST_CACHE = "public, max-age=300, s-maxage=900, stale-while-revalidate=3600, stale-if-error=86400"
NOT_FOUND_CACHE = "public, max-age=600, s-maxage=3600"


def _render(template_name: str, **ctx: Any) -> str:
    ctx.setdefault("version", _VERSION)
    ctx.setdefault("server_root_url", settings.server_root_url)
    return _jinja_env.get_template(template_name).render(**ctx)


def _not_found() -> HTMLResponse:
    return HTMLResponse(_render("404.html"), status_code=404, headers={"Cache-Control": NOT_FOUND_CACHE})


def page_context(release: ReleaseRecord) -> dict[str, Any]:
    info = release.info
    wheels: list[dict[str, Any]] = []
    formats: set[str] = set()
    for w in release.wheels:
        if not w.sboms:
            continue
        sboms = []
        for s in w.sboms:
            formats.add(s.family)
            sboms.append(
                {
                    "artifact_uuid": s.uuid,
                    "path": s.path,
                    "format": s.format,
                    "format_family": s.family,
                    "valid": s.valid,
                    "media_type": s.media_type,
                    "download_url": f"/artifact/{s.uuid}/download",
                }
            )
        wheels.append({"filename": w.filename, "url": w.url, "sboms": sboms, "attestation": w.attestation})
    wheels.sort(key=lambda w: str(w["filename"]))
    return {
        "name": release.name,
        "version": release.version,
        "summary": info.get("summary"),
        "author": info.get("author"),
        "project_urls": info.get("project_urls") or {},
        "requires_python": info.get("requires_python"),
        "license": info.get("license"),
        "classifiers": info.get("classifiers") or [],
        "wheels": wheels,
        "formats": sorted(formats),
        "has_attestation": any((w.attestation or {}).get("status") == "verified" for w in release.wheels),
    }


@router.get("/package/{name}/{pkg_version}", response_class=HTMLResponse)
async def package_page(name: str, pkg_version: str) -> HTMLResponse:
    release = await read(store.get_release, name, pkg_version)
    if release is None or not release.has_sbom:
        if release is None and await read(jobs.is_queued, name, pkg_version):
            # Queued (e.g. during a backfill): tell crawlers to come back rather than drop the page.
            return HTMLResponse(
                _render("404.html"), status_code=503, headers={"Retry-After": "3600", "Cache-Control": "no-store"}
            )
        return _not_found()
    canonical_url = f"{settings.server_root_url}/package/{name}/{pkg_version}"
    html = _render("package.html", **page_context(release), canonical_url=canonical_url)
    return HTMLResponse(html, headers={"Cache-Control": PAGE_CACHE})


@router.get("/packages", response_class=HTMLResponse)
async def packages_listing(page: int = Query(1, ge=1), format: str | None = Query(None)) -> HTMLResponse:
    if format is not None:
        families = await memoized("families", COUNT_TTL, store.sbom_families)
        if format not in families:
            return _not_found()
    total = await memoized(f"count:{format}", COUNT_TTL, store.count_packages_with_sbom, format)
    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    if page > total_pages:
        return _not_found()
    rows = await read(store.packages_with_sbom, format, (page - 1) * PAGE_SIZE, PAGE_SIZE)
    packages = [{"name": n, "version": v, "formats": f} for n, v, f in rows]

    query_parts = []
    if format:
        query_parts.append(f"format={format}")
    if page > 1:
        query_parts.append(f"page={page}")
    canonical_url = f"{settings.server_root_url}/packages" + ("?" + "&".join(query_parts) if query_parts else "")

    html = _render(
        "packages.html",
        packages=packages,
        total=total,
        page=page,
        total_pages=total_pages,
        active_format=format,
        canonical_url=canonical_url,
    )
    return HTMLResponse(html, headers={"Cache-Control": LIST_CACHE})

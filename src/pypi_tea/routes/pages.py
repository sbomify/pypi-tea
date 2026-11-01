"""Server-rendered pages for search engines, humans and AI agents. Store reads only.

Every HTML page has a Markdown twin at the same URL plus `.md` (`/index.md` for
the dashboard), and package pages a JSON twin at `.json`. The twins say what the
page says, so they carry `noindex` and point at the HTML page as canonical.
"""

import math
import re
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader
from packaging.utils import canonicalize_name

from pypi_tea import jobs, store
from pypi_tea.config import settings
from pypi_tea.lookup import memoized, read
from pypi_tea.models import ReleaseRecord

router = APIRouter()

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_jinja_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
# Markdown and plain-text templates: not HTML-escaped (third-party text goes through `md` instead),
# and block tags don't leave blank lines behind.
_text_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), trim_blocks=True, lstrip_blocks=True)
_VERSION = pkg_version("pypi-tea")

PAGE_SIZE = 50
COUNT_TTL = 60.0

PAGE_CACHE = "public, max-age=3600, s-maxage=86400, stale-while-revalidate=86400, stale-if-error=604800"
LIST_CACHE = "public, max-age=300, s-maxage=900, stale-while-revalidate=3600, stale-if-error=86400"
NOT_FOUND_CACHE = "public, max-age=600, s-maxage=3600"
_NOT_FOUND_PAGE = {"page_type": "not_found"}


_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")
_MD_URL_SAFE = ":/?#@!$&'*+,;=%~"


def md(value: object, limit: int = 0) -> str:
    """Third-party text as one line of inert Markdown: no markup, links or HTML."""
    text = " ".join(str(value or "").split())
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return _MD_SPECIAL.sub(r"\\\1", text)


def md_url(value: object) -> str:
    """A URL that can't end a Markdown link early: spaces, brackets and parentheses are encoded."""
    return quote(str(value or ""), safe=_MD_URL_SAFE)


_text_env.filters["md"] = md
_text_env.filters["md_url"] = md_url


def render(template_name: str, **ctx: Any) -> str:
    ctx.setdefault("app_version", _VERSION)
    ctx.setdefault("server_root_url", settings.server_root_url)
    ctx.setdefault("posthog_api_key", settings.posthog_api_key)
    ctx.setdefault("posthog_host", settings.posthog_host)
    env = _jinja_env if template_name.endswith(".html") else _text_env
    return env.get_template(template_name).render(**ctx)


def _not_found() -> HTMLResponse:
    return HTMLResponse(
        render("404.html", analytics_page=_NOT_FOUND_PAGE), status_code=404, headers={"Cache-Control": NOT_FOUND_CACHE}
    )


def _twin_not_found() -> PlainTextResponse:
    return PlainTextResponse("Not found\n", status_code=404, headers={"Cache-Control": NOT_FOUND_CACHE})


def twin_headers(canonical_url: str, cache: str) -> dict[str, str]:
    """Headers for a Markdown or JSON copy of a page: kept out of search, credited to the HTML page."""
    return {"Cache-Control": cache, "X-Robots-Tag": "noindex", "Link": f'<{canonical_url}>; rel="canonical"'}


def markdown_response(body: str, canonical_url: str, cache: str) -> Response:
    return Response(body, media_type="text/markdown; charset=utf-8", headers=twin_headers(canonical_url, cache))


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
                    "download_url_abs": f"{settings.server_root_url}/artifact/{s.uuid}/download",
                }
            )
        wheels.append({"filename": w.filename, "url": w.url, "sboms": sboms, "attestation": w.attestation})
    wheels.sort(key=lambda w: str(w["filename"]))
    return {
        "name": release.name,
        "version": release.version,
        "purl": f"pkg:pypi/{release.name}@{release.version}",
        "summary": info.get("summary"),
        "author": info.get("author"),
        "project_urls": info.get("project_urls") or {},
        "requires_python": info.get("requires_python"),
        "license": info.get("license"),
        "classifiers": info.get("classifiers") or [],
        "wheels": wheels,
        "formats": sorted(formats),
        "sbom_count": sum(len(w["sboms"]) for w in wheels),
        "has_attestation": any((w.attestation or {}).get("status") == "verified" for w in release.wheels),
    }


async def _load_package(name: str, pkg_version: str, suffix: str, html: bool) -> ReleaseRecord | Response:
    """The stored release with an SBOM behind a package page, or the response to send instead."""
    canonical = canonicalize_name(name)
    if canonical != name:
        # One URL per project: `/package/Ruamel.YAML/…` -> `/package/ruamel-yaml/…`.
        return RedirectResponse(
            f"/package/{quote(canonical)}/{quote(pkg_version)}{suffix}",
            status_code=301,
            headers={"Cache-Control": PAGE_CACHE},
        )
    release = await read(store.get_release, name, pkg_version)
    if release is None or not release.has_sbom:
        if release is None and await read(jobs.is_queued, name, pkg_version):
            # Queued (e.g. during a backfill): tell crawlers to come back rather than drop the page.
            headers = {"Retry-After": "3600", "Cache-Control": "no-store"}
            if html:
                page = render("404.html", analytics_page={"page_type": "package_pending"})
                return HTMLResponse(page, status_code=503, headers=headers)
            return PlainTextResponse("Being indexed, retry later\n", status_code=503, headers=headers)
        return _not_found() if html else _twin_not_found()
    return release


def _package_url(name: str, pkg_version: str) -> str:
    return f"{settings.server_root_url}/package/{name}/{pkg_version}"


# PyPI rejects local versions (`1.0+md`), so a version never ends in `.md` or `.json`
# and these routes can't shadow a real page. They are registered before the HTML route.
@router.get("/package/{name}/{pkg_version}.md")
async def package_markdown(name: str, pkg_version: str) -> Response:
    release = await _load_package(name, pkg_version, ".md", html=False)
    if isinstance(release, Response):
        return release
    canonical_url = _package_url(name, pkg_version)
    body = render("package.md", **page_context(release), canonical_url=canonical_url)
    return markdown_response(body, canonical_url, PAGE_CACHE)


@router.get("/package/{name}/{pkg_version}.json")
async def package_json(name: str, pkg_version: str) -> Response:
    release = await _load_package(name, pkg_version, ".json", html=False)
    if isinstance(release, Response):
        return release
    canonical_url = _package_url(name, pkg_version)
    ctx = page_context(release)
    for wheel in ctx["wheels"]:
        for sbom in wheel["sboms"]:
            sbom["download_url"] = sbom.pop("download_url_abs")
    data = {"url": canonical_url, "markdown_url": f"{canonical_url}.md", **ctx}
    return JSONResponse(data, headers=twin_headers(canonical_url, PAGE_CACHE))


@router.get("/package/{name}/{pkg_version}", response_class=HTMLResponse)
async def package_page(name: str, pkg_version: str) -> Response:
    release = await _load_package(name, pkg_version, "", html=True)
    if isinstance(release, Response):
        return release
    canonical_url = _package_url(name, pkg_version)
    ctx = page_context(release)
    analytics_page = {
        "page_type": "package",
        "package": name,
        "version": pkg_version,
        "sbom_formats": ctx["formats"],
        "attested": ctx["has_attestation"],
    }
    html = render(
        "package.html",
        **ctx,
        canonical_url=canonical_url,
        markdown_url=f"/package/{name}/{pkg_version}.md",
        json_url=f"/package/{name}/{pkg_version}.json",
        nav="packages",
        analytics_page=analytics_page,
    )
    return HTMLResponse(html, headers={"Cache-Control": PAGE_CACHE})


def _listing_query(format: str | None, page: int) -> str:
    query = urlencode({k: v for k, v in (("format", format), ("page", page if page > 1 else None)) if v})
    return f"?{query}" if query else ""


async def _listing(page: int, format: str | None) -> dict[str, Any] | None:
    """Template context for one page of the package listing, or None if there is no such page."""
    if format is not None:
        families = await memoized("families", COUNT_TTL, store.sbom_families)
        if format not in families:
            return None
    total = await memoized(f"count:{format}", COUNT_TTL, store.count_packages_with_sbom, format)
    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    if page > total_pages:
        return None
    rows = await read(store.packages_with_sbom, format, (page - 1) * PAGE_SIZE, PAGE_SIZE)
    return {
        "packages": [{"name": n, "version": v, "formats": f} for n, v, f in rows],
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "active_format": format,
        "canonical_url": f"{settings.server_root_url}/packages{_listing_query(format, page)}",
        "markdown_url": f"/packages.md{_listing_query(format, page)}",
        "prev_query": _listing_query(format, page - 1) if page > 1 else None,
        "next_query": _listing_query(format, page + 1) if page < total_pages else None,
    }


@router.get("/packages.md")
async def packages_markdown(page: int = Query(1, ge=1), format: str | None = Query(None)) -> Response:
    ctx = await _listing(page, format)
    if ctx is None:
        return _twin_not_found()
    return markdown_response(render("packages.md", **ctx), ctx["canonical_url"], LIST_CACHE)


@router.get("/packages", response_class=HTMLResponse)
async def packages_listing(page: int = Query(1, ge=1), format: str | None = Query(None)) -> HTMLResponse:
    ctx = await _listing(page, format)
    if ctx is None:
        return _not_found()
    html = render(
        "packages.html",
        **ctx,
        nav="packages",
        analytics_page={"page_type": "package_list", "filter_format": format or "all", "page": page},
    )
    return HTMLResponse(html, headers={"Cache-Control": LIST_CACHE})


DASHBOARD_CACHE = "public, max-age=300, s-maxage=300"


@router.get("/index.md")
async def dashboard_markdown() -> Response:
    stats = await memoized("stats", 60.0, store.stats)
    canonical_url = f"{settings.server_root_url}/"
    return markdown_response(render("index.md", stats=stats), canonical_url, DASHBOARD_CACHE)


@router.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt() -> PlainTextResponse:
    return PlainTextResponse(
        render("llms.txt", tea_spec_version=settings.tea_spec_version), headers={"Cache-Control": DASHBOARD_CACHE}
    )

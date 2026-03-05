from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.routes import artifacts, component_releases, components, discovery, product_releases, products, stats

_STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.http_client = httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "pypi-tea/0.1.0 (https://github.com/sbomify/pypi-tea)"},
    )
    app.state.cache = Cache(settings.redis_url)
    await app.state.cache.init()
    yield
    await app.state.http_client.aclose()
    await app.state.cache.close()


app = FastAPI(title="pypi-tea - TEA Server for PyPI SBOMs", lifespan=lifespan)

app.include_router(discovery.router)
app.include_router(products.router)
app.include_router(product_releases.router)
app.include_router(components.router)
app.include_router(component_releases.router)
app.include_router(artifacts.router)
app.include_router(stats.router)

# Cache headers for Cloudflare: TEA data is derived from immutable wheels
# and cached in Redis, so responses can be cached at the edge.
_CACHE_RULES: dict[str, str] = {
    "/artifact/": "public, max-age=86400, s-maxage=86400",  # SBOMs from immutable wheels
    "/component": "public, max-age=86400, s-maxage=86400",
    "/product": "public, max-age=3600, s-maxage=3600",  # Shorter — new versions may appear
    "/discovery": "public, max-age=3600, s-maxage=3600",
    "/stats": "public, max-age=60, s-maxage=60",  # Stats change frequently
}


@app.middleware("http")
async def add_cache_headers(request: Request, call_next: Any) -> Response:
    response: Response = await call_next(request)
    path = request.url.path
    for prefix, header in _CACHE_RULES.items():
        if path.startswith(prefix):
            response.headers["Cache-Control"] = header
            break
    return response


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (_STATIC_DIR / "index.html").read_text()

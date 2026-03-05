from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from pypi_tea.cache import Cache
from pypi_tea.config import settings
from pypi_tea.routes import artifacts, component_releases, components, discovery, product_releases, products, stats

_STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
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


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (_STATIC_DIR / "index.html").read_text()

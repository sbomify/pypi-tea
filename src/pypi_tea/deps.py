import httpx
from fastapi import Request

from pypi_tea.cache import Cache


def get_http_client(request: Request) -> httpx.AsyncClient:
    return request.app.state.http_client  # type: ignore[no-any-return]


def get_cache(request: Request) -> Cache:
    return request.app.state.cache  # type: ignore[no-any-return]

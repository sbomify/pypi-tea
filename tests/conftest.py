import threading
import time

import fakeredis.aioredis
import pytest
import uvicorn


@pytest.fixture(scope="session")
def tea_server():
    """Start the pypi-tea ASGI app on a free port in a background thread, using fakeredis."""
    from pypi_tea.app import app
    from pypi_tea.cache import Cache

    # Patch the cache to use fakeredis instead of a real Redis connection
    fake_cache = Cache.__new__(Cache)
    fake_cache._redis_url = "redis://fake"
    fake_cache._r = fakeredis.aioredis.FakeRedis(decode_responses=True)

    original_lifespan = app.router.lifespan_context

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def test_lifespan(app_instance):
        async with original_lifespan(app_instance) as state:
            # Override the cache with our fakeredis-backed one
            app_instance.state.cache = fake_cache
            yield state

    app.router.lifespan_context = test_lifespan

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    while not server.started:
        time.sleep(0.05)

    sockets = server.servers[0].sockets
    port = sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def tea_client(tea_server):
    """Session-scoped TeaClient pointing at the in-process server."""
    from libtea.client import TeaClient

    client = TeaClient(base_url=tea_server, timeout=30.0)
    yield client
    client.close()

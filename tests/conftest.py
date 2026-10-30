import io
import json
import re
import threading
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

from pypi_tea import db
from pypi_tea.config import settings
from pypi_tea.lookup import _memo

CDX = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}


@pytest.fixture()
def database(tmp_path: Path) -> Iterator[str]:
    """Point the app at a fresh SQLite file for one test."""
    original = settings.database_path
    path = str(tmp_path / "pypi-tea.db")
    settings.database_path = path
    db.init_schema(path)
    _memo.clear()
    yield path
    settings.database_path = original
    _memo.clear()


def make_wheel(members: dict[str, bytes], filler: int = 0) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if filler:
            # Incompressible filler so a full download is clearly distinguishable from range reads.
            zf.writestr("pkg/blob.bin", bytes(range(256)) * (filler // 256), compress_type=zipfile.ZIP_STORED)
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


_RANGE = re.compile(r"bytes=(\d+)-(\d+)")


class FakePyPI:
    """httpx transport serving the PyPI JSON API, provenance, and range-capable wheel files."""

    def __init__(self, *, ranges: bool = True) -> None:
        self.ranges = ranges
        self.releases: dict[tuple[str, str], list[tuple[str, bytes]]] = {}
        self.latest: dict[str, str] = {}
        self.requests: list[httpx.Request] = []
        self.bytes_served = 0

    def add(self, name: str, version: str, wheels: list[tuple[str, bytes]]) -> None:
        self.releases[(name, version)] = wheels
        self.latest[name] = version

    def _wheel(self, filename: str) -> bytes | None:
        for wheels in self.releases.values():
            for fn, data in wheels:
                if fn == filename:
                    return data
        return None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if m := re.fullmatch(r"/pypi/([^/]+)/([^/]+)/json", path):
            key = (m[1], m[2])
            if key not in self.releases:
                return httpx.Response(404, json={"message": "Not Found"})
            urls: list[dict[str, Any]] = [
                {
                    "filename": fn,
                    "url": f"https://files.example.com/{fn}",
                    "packagetype": "bdist_wheel",
                    "digests": {"sha256": "ab" * 32},
                    "size": len(data),
                    "upload_time_iso_8601": "2025-01-02T03:04:05.000000Z",
                }
                for fn, data in self.releases[key]
            ]
            return httpx.Response(200, json={"info": {"name": m[1], "version": m[2], "summary": "demo"}, "urls": urls})
        if m := re.fullmatch(r"/pypi/([^/]+)/json", path):
            if m[1] not in self.latest:
                return httpx.Response(404)
            return httpx.Response(200, json={"info": {"version": self.latest[m[1]]}})
        if path.startswith("/integrity/"):
            return httpx.Response(404)
        if path.startswith("/"):
            data = self._wheel(path.rsplit("/", 1)[-1])
            if data is None:
                return httpx.Response(404)
            rng = request.headers.get("range")
            if rng and self.ranges and (m := _RANGE.fullmatch(rng)):
                start, end = int(m[1]), min(int(m[2]), len(data) - 1)
                body = data[start : end + 1]
                self.bytes_served += len(body)
                return httpx.Response(206, content=body, headers={"content-range": f"bytes {start}-{end}/{len(data)}"})
            self.bytes_served += len(data)
            return httpx.Response(200, content=data)
        return httpx.Response(404)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler), base_url="https://pypi.org")


@pytest.fixture()
def fake_pypi(monkeypatch: pytest.MonkeyPatch) -> FakePyPI:
    monkeypatch.setattr(settings, "pypi_base_url", "https://pypi.org")
    monkeypatch.setattr(settings, "attestation_verification", True)
    return FakePyPI()


def sbom_wheel(name: str, version: str, sbom: dict[str, Any] | None = None, filler: int = 0) -> bytes:
    return make_wheel(
        {
            f"{name}/__init__.py": b"",
            f"{name}-{version}.dist-info/METADATA": f"Name: {name}\nVersion: {version}\n".encode(),
            f"{name}-{version}.dist-info/sboms/{name}.cdx.json": json.dumps(sbom or CDX).encode(),
        },
        filler=filler,
    )


@pytest.fixture(scope="session")
def tea_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """The real app on a free port, with an embedded worker resolving against live PyPI."""
    from pypi_tea.app import app

    path = str(tmp_path_factory.mktemp("tea") / "pypi-tea.db")
    original = (settings.database_path, settings.embedded_worker)
    settings.database_path = path
    settings.embedded_worker = True
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)
    settings.database_path, settings.embedded_worker = original


@pytest.fixture(scope="session")
def tea_client(tea_server: str) -> Iterator[Any]:
    """Session-scoped TeaClient pointing at the in-process server."""
    from libtea.client import TeaClient

    client = TeaClient(base_url=tea_server, timeout=60.0)
    yield client
    client.close()

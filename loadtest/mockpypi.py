"""Mock PyPI: JSON API + range-capable wheel files, with configurable latency."""

import asyncio
import io
import json
import os
import re
import zipfile

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

DELAY = float(os.environ.get("MOCK_DELAY", "0.2"))
ROOT = os.environ.get("MOCK_ROOT", "http://127.0.0.1:9100")


def _wheel(name: str, version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # ~1.5MB of filler so range requests matter
        zf.writestr(f"{name}/__init__.py", os.urandom(1_500_000).hex()[:1_500_000])
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [{"type": "library", "name": f"dep{i}", "version": "1.0"} for i in range(50)],
        }
        zf.writestr(f"{name}-{version}.dist-info/sboms/{name}.cdx.json", json.dumps(sbom))
        zf.writestr(f"{name}-{version}.dist-info/METADATA", f"Name: {name}\nVersion: {version}\n")
    return buf.getvalue()


_TEMPLATE = _wheel("pkg", "1.0.0")
WHEELS_PER_RELEASE = int(os.environ.get("MOCK_WHEELS", "3"))


def _filename(name: str, version: str, i: int) -> str:
    return f"{name}-{version}-cp312-cp312-manylinux_2_17_x86_64_{i}.whl"


async def version_json(request: Request) -> Response:
    await asyncio.sleep(DELAY)
    name, version = request.path_params["name"], request.path_params["version"]
    if name.startswith("missing"):
        return JSONResponse({"message": "Not Found"}, status_code=404)
    urls = [
        {
            "filename": _filename(name, version, i),
            "url": f"{ROOT}/files/{_filename(name, version, i)}",
            "packagetype": "bdist_wheel",
            "digests": {"sha256": "0" * 64},
            "size": len(_TEMPLATE),
            "upload_time_iso_8601": "2025-01-01T00:00:00.000000Z",
        }
        for i in range(WHEELS_PER_RELEASE)
    ]
    return JSONResponse(
        {"info": {"name": name, "version": version, "summary": f"{name} summary", "license": "MIT"}, "urls": urls}
    )


async def project_json(request: Request) -> Response:
    await asyncio.sleep(DELAY)
    return JSONResponse({"info": {"name": request.path_params["name"], "version": "1.0.0"}, "urls": []})


async def provenance(request: Request) -> Response:
    await asyncio.sleep(DELAY)
    return JSONResponse({"message": "not found"}, status_code=404)


_RANGE = re.compile(r"bytes=(\d*)-(\d*)")


async def wheel_file(request: Request) -> Response:
    await asyncio.sleep(DELAY)
    data = _TEMPLATE
    size = len(data)
    rng = request.headers.get("range")
    if request.method == "HEAD":
        return Response(headers={"content-length": str(size), "accept-ranges": "bytes"})
    if rng:
        m = _RANGE.match(rng)
        assert m
        start_s, end_s = m.groups()
        if start_s == "":
            start, end = size - int(end_s), size - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
        end = min(end, size - 1)
        return Response(
            data[start : end + 1],
            status_code=206,
            headers={"content-range": f"bytes {start}-{end}/{size}", "accept-ranges": "bytes"},
        )
    return Response(data, headers={"accept-ranges": "bytes"})


app = Starlette(
    routes=[
        Route("/pypi/{name}/{version}/json", version_json),
        Route("/pypi/{name}/json", project_json),
        Route("/integrity/{name}/{version}/{filename}/provenance", provenance),
        Route("/files/{filename}", wheel_file, methods=["GET", "HEAD"]),
    ]
)

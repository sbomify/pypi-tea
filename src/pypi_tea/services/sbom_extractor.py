import asyncio
import io
import logging
import zipfile
from dataclasses import dataclass

import requests
from remotezip import RemoteIOError, RemoteZip

logger = logging.getLogger("pypi_tea.sbom_extractor")

USER_AGENT = "pypi-tea/0.1.0 (https://github.com/sbomify/pypi-tea)"

SBOM_MEDIA_TYPES = {
    ".cdx.json": "application/vnd.cyclonedx+json",
    ".cdx.xml": "application/vnd.cyclonedx+xml",
    ".spdx.json": "application/spdx+json",
    ".spdx.rdf": "application/spdx+rdf",
    ".json": "application/json",
    ".xml": "application/xml",
    ".spdx": "text/spdx",
}


def _guess_media_type(path: str) -> str:
    lower = path.lower()
    for suffix, mt in SBOM_MEDIA_TYPES.items():
        if lower.endswith(suffix):
            return mt
    return "application/octet-stream"


@dataclass
class SBOMFile:
    path: str
    content: str
    media_type: str


def _extract_from_zipfile(zf: zipfile.ZipFile) -> list[SBOMFile]:
    sbom_entries = [name for name in zf.namelist() if ".dist-info/sboms/" in name and not name.endswith("/")]
    if not sbom_entries:
        return []
    sboms = []
    for entry in sbom_entries:
        content = zf.read(entry)
        sboms.append(
            SBOMFile(
                path=entry,
                content=content.decode("utf-8", errors="replace"),
                media_type=_guess_media_type(entry),
            )
        )
    return sboms


def _extract_sboms_sync(wheel_url: str) -> list[SBOMFile]:
    # Try range requests first (efficient for large wheels)
    try:
        with RemoteZip(wheel_url, headers={"User-Agent": USER_AGENT}) as rz:
            return _extract_from_zipfile(rz)
    except (RemoteIOError, Exception) as exc:
        logger.info("Range request failed for %s (%s), falling back to full download", wheel_url, exc)

    # Fallback: download the full wheel
    try:
        resp = requests.get(wheel_url, timeout=120, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            return _extract_from_zipfile(zf)
    except Exception:
        logger.exception("Failed to extract SBOMs from %s", wheel_url)
        return []


async def extract_sboms(wheel_url: str) -> list[SBOMFile]:
    return await asyncio.to_thread(_extract_sboms_sync, wheel_url)

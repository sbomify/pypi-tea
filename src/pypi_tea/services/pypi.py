from dataclasses import dataclass
from typing import Any

import httpx

from pypi_tea.config import settings


@dataclass
class WheelInfo:
    filename: str
    url: str
    digests: dict[str, str]
    size: int | None


async def get_version_metadata(client: httpx.AsyncClient, package: str, version: str) -> dict[str, Any]:
    url = f"{settings.pypi_base_url}/pypi/{package}/{version}/json"
    resp = await client.get(url)
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def extract_wheel_urls(metadata: dict[str, Any]) -> list[WheelInfo]:
    wheels = []
    for url_info in metadata.get("urls", []):
        if url_info.get("packagetype") == "bdist_wheel" or url_info.get("filename", "").endswith(".whl"):
            wheels.append(
                WheelInfo(
                    filename=url_info["filename"],
                    url=url_info["url"],
                    digests=url_info.get("digests", {}),
                    size=url_info.get("size"),
                )
            )
    return wheels

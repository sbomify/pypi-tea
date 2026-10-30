from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from pypi_tea.config import settings


@dataclass
class WheelInfo:
    filename: str
    url: str
    digests: dict[str, str]
    size: int | None


class NotOnPyPI(Exception):
    """PyPI answered 404 for the requested project or release."""


async def _get_json(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    resp = await client.get(url, follow_redirects=True)
    if resp.status_code == 404:
        raise NotOnPyPI(url)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError(f"unexpected JSON from {url}")
    return data


async def get_version_metadata(client: httpx.AsyncClient, package: str, version: str) -> dict[str, Any]:
    return await _get_json(client, f"{settings.pypi_base_url}/pypi/{package}/{version}/json")


async def get_latest_version(client: httpx.AsyncClient, package: str) -> str | None:
    data = await _get_json(client, f"{settings.pypi_base_url}/pypi/{package}/json")
    version = data.get("info", {}).get("version")
    return version if isinstance(version, str) and version else None


OS_TAG_MAP: dict[str, list[str]] = {
    "linux": ["linux", "manylinux", "musllinux"],
    "darwin": ["macosx"],
    "macos": ["macosx"],
    "macosx": ["macosx"],
    "windows": ["win"],
    "win": ["win"],
}

ARCH_TAG_MAP: dict[str, list[str]] = {
    "x86_64": ["x86_64", "amd64"],
    "amd64": ["x86_64", "amd64"],
    "aarch64": ["aarch64", "arm64"],
    "arm64": ["aarch64", "arm64"],
    "i686": ["i686"],
    "x86": ["i686"],
    "ppc64le": ["ppc64le"],
    "s390x": ["s390x"],
    "universal2": ["universal2"],
}


class _HasFilename(Protocol):
    @property
    def filename(self) -> str: ...


def filter_wheels_by_platform[W: _HasFilename](
    wheels: list[W], os_filter: str | None = None, arch_filter: str | None = None
) -> list[W]:
    if not os_filter and not arch_filter:
        return wheels

    os_substrings = OS_TAG_MAP.get(os_filter.lower(), [os_filter.lower()]) if os_filter else None
    arch_substrings = ARCH_TAG_MAP.get(arch_filter.lower(), [arch_filter.lower()]) if arch_filter else None

    result: list[W] = []
    for wheel in wheels:
        try:
            _, _, _, tags = parse_wheel_filename(wheel.filename)
        except InvalidWheelFilename:
            result.append(wheel)
            continue

        platform_strs = [t.platform for t in tags]

        if all(p == "any" for p in platform_strs):
            result.append(wheel)
            continue

        os_match = os_substrings is None or any(any(sub in p for sub in os_substrings) for p in platform_strs)
        arch_match = arch_substrings is None or any(any(sub in p for sub in arch_substrings) for p in platform_strs)

        if os_match and arch_match:
            result.append(wheel)

    return result


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

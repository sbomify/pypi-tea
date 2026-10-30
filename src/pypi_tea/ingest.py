"""Resolve one PyPI release into stored records. Runs in the worker only.

Wheels are immutable, so a wheel that was inspected before is never fetched
again: re-resolving a known release costs one PyPI JSON request.
"""

import asyncio
import hashlib
import logging
from typing import Any

import httpx

from pypi_tea import db, store
from pypi_tea.config import settings
from pypi_tea.models import ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.services.attestation import check_wheel_attestation
from pypi_tea.services.pypi import NotOnPyPI, WheelInfo, extract_wheel_urls, get_latest_version, get_version_metadata
from pypi_tea.services.sbom_format import detect_sbom_format, validate_sbom
from pypi_tea.services.uuids import artifact_uuid
from pypi_tea.services.wheel_reader import WheelError, read_members

logger = logging.getLogger("pypi_tea.ingest")

SBOM_DIR = ".dist-info/sboms/"
_INFO_FIELDS = ("summary", "author", "license", "requires_python", "project_urls", "classifiers")
_MAX_INFO_TEXT = 2000
# Attestation results worth keeping; anything else is re-checked on the next resolve.
_FINAL_ATTESTATION = frozenset({"verified", "not_available"})


def _trim_info(info: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in _INFO_FIELDS:
        value = info.get(key)
        if isinstance(value, str) and len(value) > _MAX_INFO_TEXT:
            value = value[:_MAX_INFO_TEXT] + "…"
        out[key] = value
    return out


async def _inspect_wheel(client: httpx.AsyncClient, wheel: WheelInfo) -> tuple[list[SbomRecord], str | None]:
    try:
        members = await read_members(client, wheel.url, wheel.size, lambda n: SBOM_DIR in n)
    except WheelError as e:
        logger.info("cannot inspect %s: %s", wheel.filename, e)
        return [], str(e)
    sboms: list[SbomRecord] = []
    for path in sorted(members):
        content = members[path].decode("utf-8", errors="replace")
        fmt, media_type = detect_sbom_format(content)
        if fmt is None or media_type is None:
            logger.warning("unrecognised SBOM format in %s: %s", wheel.filename, path)
            continue
        valid = await asyncio.to_thread(validate_sbom, content, fmt, media_type)
        sboms.append(
            SbomRecord(
                uuid=artifact_uuid(wheel.url, path),
                path=path,
                media_type=media_type,
                sha256=hashlib.sha256(content.encode()).hexdigest(),
                format=fmt,
                valid=valid,
                content=content,
            )
        )
    return sboms, None


async def _resolve_wheel(
    client: httpx.AsyncClient, name: str, version: str, wheel: WheelInfo, previous: WheelRecord | None
) -> WheelRecord:
    if previous is not None:
        contents = await asyncio.to_thread(_stored_contents, wheel.url)
        sboms = [s for s in previous.sboms if s.path in contents]
        for s in sboms:
            s.content = contents[s.path]
        error = previous.error
    else:
        sboms, error = await _inspect_wheel(client, wheel)

    attestation = previous.attestation if previous is not None else None
    if attestation is None or attestation.get("status") not in _FINAL_ATTESTATION:
        result = await check_wheel_attestation(client, name, version, wheel.filename, wheel.digests.get("sha256"))
        attestation = result.to_dict()

    return WheelRecord(
        url=wheel.url,
        filename=wheel.filename,
        digests=wheel.digests,
        size=wheel.size,
        sboms=sboms,
        attestation=attestation,
        error=error,
    )


def _stored_contents(wheel_url: str) -> dict[str, str]:
    return store.get_stored_sbom_contents(db.writer(settings.database_path), wheel_url)


def _previous(name: str, version: str) -> ReleaseRecord | None:
    return store.get_release(db.writer(settings.database_path), name, version)


def _save(release: ReleaseRecord) -> None:
    store.save_release(db.writer(settings.database_path), release)


def _mark_missing(name: str, version: str) -> None:
    store.mark_missing(db.writer(settings.database_path), name, version)


async def ingest_release(client: httpx.AsyncClient, name: str, version: str) -> ReleaseRecord | None:
    """Fetch, inspect and store one release. Returns None if PyPI doesn't have it."""
    try:
        metadata = await get_version_metadata(client, name, version)
    except NotOnPyPI:
        await asyncio.to_thread(_mark_missing, name, version)
        return None

    urls = metadata.get("urls") or []
    created = urls[0].get("upload_time_iso_8601") if urls else None
    wheels = extract_wheel_urls(metadata)
    previous = await asyncio.to_thread(_previous, name, version)
    previous_wheels = {w.url: w for w in previous.wheels} if previous else {}

    sem = asyncio.Semaphore(settings.wheel_concurrency)

    async def one(wheel: WheelInfo) -> WheelRecord:
        async with sem:
            return await _resolve_wheel(client, name, version, wheel, previous_wheels.get(wheel.url))

    records = await asyncio.gather(*(one(w) for w in wheels))
    release = ReleaseRecord(
        name=name,
        version=version,
        created=created,
        info=_trim_info(metadata.get("info") or {}),
        wheels=list(records),
    )
    await asyncio.to_thread(_save, release)
    logger.info(
        "resolved %s@%s: %d wheels, %d with SBOMs", name, version, len(wheels), sum(w.has_sbom for w in records)
    )
    return release


async def latest_version(client: httpx.AsyncClient, name: str) -> str | None:
    try:
        return await get_latest_version(client, name)
    except NotOnPyPI:
        return None

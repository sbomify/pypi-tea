import json
import time
from typing import Any

import redis.asyncio as redis

PYPI_TTL = 3600  # 1 hour
SBOM_TTL = 86400  # 24 hours
NEGATIVE_TTL = 86400  # 24 hours
ATTESTATION_TTL = 86400  # 24 hours

STATS_KEY = "stats"
STATS_BUCKET_PREFIX = "stats:ts:"
STATS_BUCKET_SIZE = 86400  # 24 hours
STATS_RETENTION = 86400 * 30  # 30 days

# Persistent sets for accurate unique counting (no TTL)
UNIQUE_PACKAGES = "unique:packages"
UNIQUE_PACKAGES_WITH_SBOM = "unique:packages_with_sbom"
UNIQUE_WHEELS_WITH_SBOM = "unique:wheels_with_sbom"
UNIQUE_WHEELS_WITHOUT_SBOM = "unique:wheels_without_sbom"
UNIQUE_SBOM_FORMATS_TRACKED = "unique:sbom_formats_tracked"
UNIQUE_SBOM_VALIDATION = "unique:sbom_validation"
UNIQUE_SBOM_ENCODINGS = "unique:sbom_encodings"
UNIQUE_ATTESTATION_STATUS = "unique:attestation_status"
UNIQUE_ATTESTATION_PUBLISHERS = "unique:attestation_publishers"

# Daily set prefixes for time series (with TTL)
DAILY_PACKAGES_PREFIX = "daily:packages:"
DAILY_PACKAGES_WITH_SBOM_PREFIX = "daily:packages_with_sbom:"

# Usage tracking
USAGE_TOP_PACKAGES = "usage:top_packages"
USAGE_QUALIFIERS_OS = "usage:qualifiers:os"
USAGE_QUALIFIERS_ARCH = "usage:qualifiers:arch"
USAGE_ENDPOINTS = "usage:endpoints"
USAGE_RECENT = "usage:recent"
USAGE_RECENT_MAX = 100
USAGE_DAILY_QUERIES_PREFIX = "usage:daily_queries:"
USAGE_QUALIFIER_QUERIES = "usage:qualifier_query_count"

# Per-package format tracking for SEO pages
PKG_FORMATS_PREFIX = "pkg_formats:"  # pkg_formats:{name}@{version} → set of format strings
FORMAT_PACKAGES_PREFIX = "format_pkgs:"  # format_pkgs:{family} → set of name@version


def _current_bucket() -> int:
    return int(time.time()) // STATS_BUCKET_SIZE * STATS_BUCKET_SIZE


class Cache:
    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._r: redis.Redis | None = None

    async def init(self) -> None:
        self._r = redis.from_url(self._redis_url, decode_responses=True)

    async def close(self) -> None:
        if self._r:
            await self._r.aclose()

    @property
    def _client(self) -> redis.Redis:
        assert self._r is not None
        return self._r

    async def _incr_stat(self, field: str) -> None:
        bucket = _current_bucket()
        bucket_key = f"{STATS_BUCKET_PREFIX}{bucket}"
        pipe = self._client.pipeline()
        pipe.hincrby(STATS_KEY, field, 1)
        pipe.hincrby(bucket_key, field, 1)
        pipe.expire(bucket_key, STATS_RETENTION)
        await pipe.execute()

    # --- PyPI metadata ---

    async def get_pypi_metadata(self, package: str, version: str) -> dict[str, Any] | None:
        data = await self._client.get(f"pypi:{package}:{version}")
        if data is None:
            await self._incr_stat("pypi:miss")
            return None
        await self._incr_stat("pypi:hit")
        return json.loads(data)  # type: ignore[no-any-return]

    async def set_pypi_metadata(self, package: str, version: str, data: dict[str, Any]) -> None:
        await self._client.set(f"pypi:{package}:{version}", json.dumps(data), ex=PYPI_TTL)

    # --- SBOM content ---

    async def get_sbom_content(self, wheel_url: str) -> list[dict[str, Any]] | None:
        data = await self._client.get(f"sbom:{wheel_url}")
        if data is None:
            await self._incr_stat("sbom:miss")
            return None
        await self._incr_stat("sbom:hit")
        return json.loads(data)  # type: ignore[no-any-return]

    async def set_sbom_content(self, wheel_url: str, sboms: list[dict[str, Any]]) -> None:
        await self._client.set(f"sbom:{wheel_url}", json.dumps(sboms), ex=SBOM_TTL)
        await self._client.sadd(UNIQUE_WHEELS_WITH_SBOM, wheel_url)  # type: ignore[misc]

    # --- Negative cache ---

    async def is_negative_cached(self, wheel_url: str) -> bool:
        exists = bool(await self._client.exists(f"neg:{wheel_url}"))
        if exists:
            await self._incr_stat("negative:hit")
        else:
            await self._incr_stat("negative:miss")
        return exists

    async def set_negative_cache(self, wheel_url: str) -> None:
        await self._client.set(f"neg:{wheel_url}", "1", ex=NEGATIVE_TTL)
        await self._client.sadd(UNIQUE_WHEELS_WITHOUT_SBOM, wheel_url)  # type: ignore[misc]

    # --- SBOM format tracking ---

    async def track_sbom_format(self, sbom_id: str, format_key: str) -> None:
        """Track SBOM format for a unique SBOM file.

        Stores the format per sbom_id in a hash map. This is idempotent and
        self-correcting: if the same sbom_id is tracked again with the same
        format, it's a no-op; if the format changes, both old and new counts
        are updated.
        """
        previous: str | None = await self._client.hget(UNIQUE_SBOM_FORMATS_TRACKED, sbom_id)  # type: ignore[misc]
        if previous == format_key:
            return  # already tracked correctly
        pipe = self._client.pipeline()
        pipe.hset(UNIQUE_SBOM_FORMATS_TRACKED, sbom_id, format_key)
        if previous:
            pipe.hincrby(STATS_KEY, f"sbom_format:{previous}", -1)
        pipe.hincrby(STATS_KEY, f"sbom_format:{format_key}", 1)
        await pipe.execute()

    async def track_sbom_validation(self, sbom_id: str, valid: bool) -> None:
        """Track SBOM validation result. Same idempotent pattern as track_sbom_format."""
        result = "valid" if valid else "invalid"
        previous: str | None = await self._client.hget(UNIQUE_SBOM_VALIDATION, sbom_id)  # type: ignore[misc]
        if previous == result:
            return
        pipe = self._client.pipeline()
        pipe.hset(UNIQUE_SBOM_VALIDATION, sbom_id, result)
        if previous:
            pipe.hincrby(STATS_KEY, f"sbom_validation:{previous}", -1)
        pipe.hincrby(STATS_KEY, f"sbom_validation:{result}", 1)
        await pipe.execute()

    async def track_sbom_encoding(self, sbom_id: str, media_type: str) -> None:
        """Track SBOM encoding (media type). Same idempotent pattern."""
        previous: str | None = await self._client.hget(UNIQUE_SBOM_ENCODINGS, sbom_id)  # type: ignore[misc]
        if previous == media_type:
            return
        pipe = self._client.pipeline()
        pipe.hset(UNIQUE_SBOM_ENCODINGS, sbom_id, media_type)
        if previous:
            pipe.hincrby(STATS_KEY, f"sbom_encoding:{previous}", -1)
        pipe.hincrby(STATS_KEY, f"sbom_encoding:{media_type}", 1)
        await pipe.execute()

    # --- Attestation cache ---

    async def get_attestation(self, wheel_url: str) -> dict[str, Any] | None:
        data = await self._client.get(f"att:{wheel_url}")
        if data is None:
            return None
        return json.loads(data)  # type: ignore[no-any-return]

    async def set_attestation(self, wheel_url: str, result: dict[str, Any]) -> None:
        await self._client.set(f"att:{wheel_url}", json.dumps(result), ex=ATTESTATION_TTL)

    async def track_attestation_status(self, wheel_url: str, status: str) -> None:
        """Track attestation status per wheel. Same idempotent pattern as track_sbom_format."""
        previous: str | None = await self._client.hget(UNIQUE_ATTESTATION_STATUS, wheel_url)  # type: ignore[misc]
        if previous == status:
            return
        pipe = self._client.pipeline()
        pipe.hset(UNIQUE_ATTESTATION_STATUS, wheel_url, status)
        if previous:
            pipe.hincrby(STATS_KEY, f"attestation:{previous}", -1)
        pipe.hincrby(STATS_KEY, f"attestation:{status}", 1)
        await pipe.execute()

    async def track_attestation_publisher(self, wheel_url: str, publisher_kind: str) -> None:
        """Track attestation publisher per wheel. Same idempotent pattern."""
        previous: str | None = await self._client.hget(UNIQUE_ATTESTATION_PUBLISHERS, wheel_url)  # type: ignore[misc]
        if previous == publisher_kind:
            return
        pipe = self._client.pipeline()
        pipe.hset(UNIQUE_ATTESTATION_PUBLISHERS, wheel_url, publisher_kind)
        if previous:
            pipe.hincrby(STATS_KEY, f"attestation_publisher:{previous}", -1)
        pipe.hincrby(STATS_KEY, f"attestation_publisher:{publisher_kind}", 1)
        await pipe.execute()

    # --- Package-level tracking ---

    async def track_package_query(self, package: str, version: str, has_sbom: bool) -> None:
        """Track a unique package@version query for community-facing stats."""
        key = f"{package}@{version}"
        bucket = _current_bucket()
        pipe = self._client.pipeline()
        pipe.sadd(UNIQUE_PACKAGES, key)
        daily_key = f"{DAILY_PACKAGES_PREFIX}{bucket}"
        pipe.sadd(daily_key, key)
        pipe.expire(daily_key, STATS_RETENTION)
        if has_sbom:
            pipe.sadd(UNIQUE_PACKAGES_WITH_SBOM, key)
            daily_sbom_key = f"{DAILY_PACKAGES_WITH_SBOM_PREFIX}{bucket}"
            pipe.sadd(daily_sbom_key, key)
            pipe.expire(daily_sbom_key, STATS_RETENTION)
        await pipe.execute()

    # --- UUID lookup ---

    async def get_uuid_lookup(self, uuid: str) -> dict[str, Any] | None:
        data = await self._client.get(f"uuid:{uuid}")
        if data is None:
            return None
        return json.loads(data)  # type: ignore[no-any-return]

    async def set_uuid_lookup(self, uuid: str, entity_type: str, data: dict[str, Any]) -> None:
        payload = {"entity_type": entity_type, **data}
        await self._client.set(f"uuid:{uuid}", json.dumps(payload))
        await self._client.sadd(f"etype:{entity_type}", uuid)  # type: ignore[misc]

    async def find_by_entity_type_and_field(self, entity_type: str, field: str, value: str) -> list[dict[str, Any]]:
        uuids = await self._client.smembers(f"etype:{entity_type}")  # type: ignore[misc]
        if not uuids:
            return []
        results: list[dict[str, Any]] = []
        pipe = self._client.pipeline()
        uuid_list = sorted(uuids)
        for uuid in uuid_list:
            pipe.get(f"uuid:{uuid}")
        values = await pipe.execute()
        for uuid, raw in zip(uuid_list, values, strict=True):
            if raw is None:
                continue
            data: dict[str, Any] = json.loads(raw)
            if data.get(field) == value:
                results.append({"uuid": uuid, **data})
        return results

    async def list_by_entity_type(
        self, entity_type: str, offset: int = 0, limit: int = 100
    ) -> tuple[list[dict[str, Any]], int]:
        uuids = await self._client.smembers(f"etype:{entity_type}")  # type: ignore[misc]
        total = len(uuids)
        if not uuids:
            return [], 0
        uuid_list = sorted(uuids)[offset : offset + limit]
        if not uuid_list:
            return [], total
        pipe = self._client.pipeline()
        for uuid in uuid_list:
            pipe.get(f"uuid:{uuid}")
        values = await pipe.execute()
        results: list[dict[str, Any]] = []
        for uuid, raw in zip(uuid_list, values, strict=True):
            if raw is not None:
                data: dict[str, Any] = json.loads(raw)
                results.append({"uuid": uuid, **data})
        return results, total

    async def get_invalid_sboms(self) -> list[dict[str, str]]:
        """Return details of all SBOMs that failed validation."""
        all_results: dict[str, str] = await self._client.hgetall(UNIQUE_SBOM_VALIDATION)  # type: ignore[misc]
        invalid_ids = [sbom_id for sbom_id, result in all_results.items() if result == "invalid"]
        if not invalid_ids:
            return []

        # sbom_id is "wheel_url:dist-info-path/sboms/filename"
        # Extract package name from the wheel URL
        results: list[dict[str, str]] = []
        for sbom_id in sorted(invalid_ids):
            # Split on first ".dist-info/sboms/" to separate wheel_url from sbom_path
            parts = sbom_id.split(".dist-info/sboms/", 1)
            wheel_url = parts[0] + ".dist-info/sboms/" + parts[1] if len(parts) == 2 else sbom_id
            # The wheel_url portion before .dist-info contains the filename
            # e.g. https://files.pythonhosted.org/.../maturin-1.8.1-cp39-...whl:maturin-1.8.1.dist-info/sboms/...
            # Reconstruct: everything before the colon-separated path is the wheel URL
            colon_idx = sbom_id.find(":")
            if colon_idx > 0 and "://" in sbom_id[:colon_idx]:
                # URL contains ://, find the next colon after the path
                after_scheme = sbom_id.find("://") + 3
                path_colon = sbom_id.find(":", after_scheme)
                if path_colon > 0:
                    wheel_url = sbom_id[:path_colon]
                    sbom_path = sbom_id[path_colon + 1 :]
                else:
                    wheel_url = sbom_id
                    sbom_path = ""
            else:
                wheel_url = sbom_id
                sbom_path = ""

            # Extract package name from wheel filename in URL
            filename = wheel_url.rsplit("/", 1)[-1] if "/" in wheel_url else wheel_url
            # Wheel filename format: name-version-...whl
            name_parts = filename.split("-")
            package = name_parts[0] if name_parts else "unknown"
            version = name_parts[1] if len(name_parts) > 1 else "unknown"

            # Get format info
            fmt: str | None = await self._client.hget(UNIQUE_SBOM_FORMATS_TRACKED, sbom_id)  # type: ignore[misc]

            entry: dict[str, str] = {
                "package": package,
                "version": version,
                "sbom_path": sbom_path,
                "wheel_url": wheel_url,
            }
            if fmt:
                entry["format"] = fmt
            results.append(entry)

        return results

    # --- Per-package format tracking (for SEO pages) ---

    async def track_package_format(self, package: str, version: str, format_key: str) -> None:
        """Index SBOM format per package for browsing/filtering."""
        key = f"{package}@{version}"
        family = format_key.split("/")[0]  # "CycloneDX/1.6" → "CycloneDX"
        pipe = self._client.pipeline()
        pipe.sadd(f"{PKG_FORMATS_PREFIX}{key}", format_key)
        pipe.sadd(f"{FORMAT_PACKAGES_PREFIX}{family}", key)
        await pipe.execute()

    async def get_packages_with_sbom(self, offset: int = 0, limit: int = 0) -> tuple[list[str], int]:
        """Return sorted package@version strings from the SBOM set."""
        members: set[str] = await self._client.smembers(UNIQUE_PACKAGES_WITH_SBOM)  # type: ignore[misc]
        total = len(members)
        items = sorted(members)
        if limit > 0:
            items = items[offset : offset + limit]
        return items, total

    async def get_packages_with_sbom_by_format(
        self, format_family: str, offset: int = 0, limit: int = 50
    ) -> tuple[list[str], int]:
        """Return packages filtered by SBOM format family (e.g. 'CycloneDX', 'SPDX')."""
        # Intersect format index with packages-with-sbom to ensure consistency
        family_members: set[str] = await self._client.smembers(f"{FORMAT_PACKAGES_PREFIX}{format_family}")  # type: ignore[misc]
        sbom_members: set[str] = await self._client.smembers(UNIQUE_PACKAGES_WITH_SBOM)  # type: ignore[misc]
        matched = sorted(family_members & sbom_members)
        total = len(matched)
        items = matched[offset : offset + limit]
        return items, total

    async def get_package_formats(self, package: str, version: str) -> list[str]:
        """Return SBOM format strings for a package (e.g. ['CycloneDX/1.6'])."""
        members: set[str] = await self._client.smembers(f"{PKG_FORMATS_PREFIX}{package}@{version}")  # type: ignore[misc]
        return sorted(members)

    async def get_package_page_data(self, package: str, version: str) -> dict[str, Any] | None:
        """Aggregate all data needed to render a package SEO page."""
        key = f"{package}@{version}"
        is_member: bool = await self._client.sismember(UNIQUE_PACKAGES_WITH_SBOM, key)  # type: ignore[misc]
        if not is_member:
            return None

        # PyPI metadata (may have expired — gracefully degrade)
        metadata = await self.get_pypi_metadata(package, version)
        info = metadata.get("info", {}) if metadata else {}

        # Find all artifacts for this package+version via UUID lookups
        artifacts = await self.find_by_entity_type_and_field("artifact", "name", package)
        artifacts = [a for a in artifacts if a.get("version") == version]

        # Find all component_releases (wheels) for this package+version
        comp_releases = await self.find_by_entity_type_and_field("component_release", "name", package)
        comp_releases = [cr for cr in comp_releases if cr.get("version") == version]

        # Build wheel → sbom mapping
        wheels_map: dict[str, dict[str, Any]] = {}
        for cr in comp_releases:
            filename = cr.get("filename", "")
            url = cr.get("url", "")
            if filename and url:
                wheels_map[url] = {"filename": filename, "url": url, "sboms": []}

        # Populate SBOMs per wheel
        format_set: set[str] = set()
        for art in artifacts:
            wheel_url = art.get("wheel_url", "")
            sbom_path = art.get("sbom_path", "")
            a_uuid = art.get("uuid", "")
            sbom_id = f"{wheel_url}:{sbom_path}"

            # Get format and validation from tracking hashes
            pipe = self._client.pipeline()
            pipe.hget(UNIQUE_SBOM_FORMATS_TRACKED, sbom_id)
            pipe.hget(UNIQUE_SBOM_VALIDATION, sbom_id)
            pipe.hget(UNIQUE_SBOM_ENCODINGS, sbom_id)
            fmt_raw, valid_raw, encoding_raw = await pipe.execute()

            fmt: str | None = fmt_raw
            family = fmt.split("/")[0] if fmt else None
            valid: bool | None = valid_raw == "valid" if valid_raw else None
            media_type: str = encoding_raw or "application/octet-stream"

            if family:
                format_set.add(family)

            sbom_entry = {
                "artifact_uuid": a_uuid,
                "path": sbom_path,
                "format": fmt,
                "format_family": family,
                "valid": valid,
                "media_type": media_type,
                "download_url": f"/artifact/{a_uuid}/download",
            }

            if wheel_url in wheels_map:
                wheels_map[wheel_url]["sboms"].append(sbom_entry)
            else:
                # Wheel not in comp_releases (shouldn't happen, but be safe)
                filename = wheel_url.rsplit("/", 1)[-1] if "/" in wheel_url else wheel_url
                wheels_map[wheel_url] = {"filename": filename, "url": wheel_url, "sboms": [sbom_entry]}

        # Only include wheels that have SBOMs
        wheels = [w for w in wheels_map.values() if w["sboms"]]
        wheels.sort(key=lambda w: w["filename"])

        return {
            "name": package,
            "version": version,
            "summary": info.get("summary"),
            "author": info.get("author"),
            "project_urls": info.get("project_urls") or {},
            "requires_python": info.get("requires_python"),
            "license": info.get("license"),
            "classifiers": info.get("classifiers") or [],
            "wheels": wheels,
            "formats": sorted(format_set),
        }

    # --- Usage tracking ---

    async def track_query(
        self,
        package: str,
        version: str,
        os_filter: str | None,
        arch_filter: str | None,
        has_sbom: bool,
    ) -> None:
        bucket = _current_bucket()
        daily_key = f"{USAGE_DAILY_QUERIES_PREFIX}{bucket}"
        entry = json.dumps(
            {
                "package": package,
                "version": version,
                "os": os_filter,
                "arch": arch_filter,
                "has_sbom": has_sbom,
                "ts": int(time.time()),
            }
        )
        pipe = self._client.pipeline()
        pipe.zincrby(USAGE_TOP_PACKAGES, 1, f"{package}@{version}")
        if os_filter:
            pipe.zincrby(USAGE_QUALIFIERS_OS, 1, os_filter)
            pipe.hincrby(STATS_KEY, USAGE_QUALIFIER_QUERIES, 1)
        if arch_filter:
            pipe.zincrby(USAGE_QUALIFIERS_ARCH, 1, arch_filter)
            if not os_filter:
                pipe.hincrby(STATS_KEY, USAGE_QUALIFIER_QUERIES, 1)
        pipe.lpush(USAGE_RECENT, entry)
        pipe.ltrim(USAGE_RECENT, 0, USAGE_RECENT_MAX - 1)
        pipe.incr(daily_key)
        pipe.expire(daily_key, STATS_RETENTION)
        await pipe.execute()

    async def track_endpoint(self, endpoint: str) -> None:
        await self._client.zincrby(USAGE_ENDPOINTS, 1, endpoint)

    async def get_usage_stats(self) -> dict[str, Any]:
        pipe = self._client.pipeline()
        pipe.zrevrange(USAGE_TOP_PACKAGES, 0, 19, withscores=True)
        pipe.zrevrange(USAGE_QUALIFIERS_OS, 0, 9, withscores=True)
        pipe.zrevrange(USAGE_QUALIFIERS_ARCH, 0, 9, withscores=True)
        pipe.zrevrange(USAGE_ENDPOINTS, 0, 19, withscores=True)
        pipe.lrange(USAGE_RECENT, 0, USAGE_RECENT_MAX - 1)
        pipe.hget(STATS_KEY, USAGE_QUALIFIER_QUERIES)
        results = await pipe.execute()

        top_packages = [{"package": name, "queries": int(score)} for name, score in results[0]]
        qualifier_os = {name: int(score) for name, score in results[1]}
        qualifier_arch = {name: int(score) for name, score in results[2]}
        endpoints = {name: int(score) for name, score in results[3]}
        recent = [json.loads(entry) for entry in results[4]]
        qualifier_query_count = int(results[5] or 0)

        # Daily query time series
        now = int(time.time())
        oldest = now - STATS_RETENTION
        oldest_bucket = oldest // STATS_BUCKET_SIZE * STATS_BUCKET_SIZE
        current = _current_bucket()
        bucket_times: list[int] = []
        t = oldest_bucket
        while t <= current:
            bucket_times.append(t)
            t += STATS_BUCKET_SIZE

        daily_series: list[dict[str, Any]] = []
        if bucket_times:
            daily_pipe = self._client.pipeline()
            for bt in bucket_times:
                daily_pipe.get(f"{USAGE_DAILY_QUERIES_PREFIX}{bt}")
            daily_results = await daily_pipe.execute()
            for bt, count_raw in zip(bucket_times, daily_results, strict=True):
                count = int(count_raw) if count_raw else 0
                if count > 0:
                    daily_series.append({"timestamp": bt, "queries": count})

        total_queries = sum(int(score) for _, score in results[0]) if results[0] else 0

        return {
            "total_queries": total_queries,
            "qualifier_queries": qualifier_query_count,
            "top_packages": top_packages,
            "qualifiers": {
                "os": qualifier_os,
                "arch": qualifier_arch,
            },
            "endpoints": endpoints,
            "recent": recent,
            "daily_queries": daily_series,
        }

    # --- Statistics ---

    @staticmethod
    def _extract_sbom_formats(counters: dict[str, int]) -> dict[str, int]:
        return {k.removeprefix("sbom_format:"): v for k, v in counters.items() if k.startswith("sbom_format:")}

    @staticmethod
    def _extract_sbom_validation(counters: dict[str, int]) -> dict[str, int]:
        return {k.removeprefix("sbom_validation:"): v for k, v in counters.items() if k.startswith("sbom_validation:")}

    @staticmethod
    def _extract_sbom_encodings(counters: dict[str, int]) -> dict[str, int]:
        return {k.removeprefix("sbom_encoding:"): v for k, v in counters.items() if k.startswith("sbom_encoding:")}

    @staticmethod
    def _extract_attestations(counters: dict[str, int]) -> dict[str, int]:
        return {
            k.removeprefix("attestation:"): v
            for k, v in counters.items()
            if k.startswith("attestation:") and not k.startswith("attestation_publisher:")
        }

    @staticmethod
    def _extract_attestation_publishers(counters: dict[str, int]) -> dict[str, int]:
        return {
            k.removeprefix("attestation_publisher:"): v
            for k, v in counters.items()
            if k.startswith("attestation_publisher:")
        }

    async def get_stats(self) -> dict[str, Any]:
        raw = await self._client.hgetall(STATS_KEY)  # type: ignore[misc]
        counters: dict[str, int] = {k: int(v) for k, v in raw.items()}

        pipe = self._client.pipeline()
        pipe.scard(UNIQUE_PACKAGES)
        pipe.scard(UNIQUE_PACKAGES_WITH_SBOM)
        pipe.scard(UNIQUE_WHEELS_WITH_SBOM)
        pipe.scard(UNIQUE_WHEELS_WITHOUT_SBOM)
        pkg_total, pkg_with_sbom, wheels_with, wheels_without = await pipe.execute()

        wheels_total = wheels_with + wheels_without

        return {
            "packages": {
                "total_explored": pkg_total,
                "with_sbom": pkg_with_sbom,
                "without_sbom": pkg_total - pkg_with_sbom,
                "sbom_percentage": round(pkg_with_sbom / pkg_total * 100, 2) if pkg_total else None,
            },
            "wheels": {
                "total_checked": wheels_total,
                "with_sbom": wheels_with,
                "without_sbom": wheels_without,
                "sbom_percentage": round(wheels_with / wheels_total * 100, 2) if wheels_total else None,
            },
            "sbom_formats": self._extract_sbom_formats(counters),
            "sbom_validation": self._extract_sbom_validation(counters),
            "sbom_encodings": self._extract_sbom_encodings(counters),
            "attestations": self._extract_attestations(counters),
            "attestation_publishers": self._extract_attestation_publishers(counters),
        }

    async def get_stats_timeseries(self) -> list[dict[str, Any]]:
        now = int(time.time())
        oldest = now - STATS_RETENTION
        oldest_bucket = oldest // STATS_BUCKET_SIZE * STATS_BUCKET_SIZE
        current = _current_bucket()

        bucket_times: list[int] = []
        t = oldest_bucket
        while t <= current:
            bucket_times.append(t)
            t += STATS_BUCKET_SIZE

        if not bucket_times:
            return []

        pipe = self._client.pipeline()
        for bt in bucket_times:
            pipe.scard(f"{DAILY_PACKAGES_PREFIX}{bt}")
            pipe.scard(f"{DAILY_PACKAGES_WITH_SBOM_PREFIX}{bt}")
            pipe.hgetall(f"{STATS_BUCKET_PREFIX}{bt}")
        results = await pipe.execute()

        series: list[dict[str, Any]] = []
        for i, bt in enumerate(bucket_times):
            pkg_new = results[i * 3]
            pkg_with_sbom_new = results[i * 3 + 1]
            raw = results[i * 3 + 2]

            if not pkg_new and not raw:
                continue

            counters: dict[str, int] = {k: int(v) for k, v in raw.items()} if raw else {}

            series.append(
                {
                    "timestamp": bt,
                    "packages": {
                        "new_explored": pkg_new,
                        "new_with_sbom": pkg_with_sbom_new,
                    },
                    "sbom_formats": self._extract_sbom_formats(counters),
                }
            )
        return series

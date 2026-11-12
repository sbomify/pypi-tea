"""Queries over the SQLite store.

Every read here is an indexed lookup or an index-ordered range scan; nothing on
the read path sorts or scans a whole table. Writes happen in the worker, one
release per transaction, and keep the `counters` behind /stats and the catalog
listings current as they go.
"""

import hashlib
import json
import sqlite3
import time
import zlib
from collections import Counter
from typing import Any

from packaging.utils import canonicalize_name

from pypi_tea.db import begin
from pypi_tea.models import Entity, ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.services.uuids import (
    artifact_uuid,
    component_release_uuid,
    component_uuid,
    product_release_uuid,
    product_uuid,
)

MISSING_TTL = 3600

# --- reads ---


def _wheel_from_row(row: sqlite3.Row) -> WheelRecord:
    return WheelRecord(
        url=row["url"],
        filename=row["filename"],
        digests=json.loads(row["digests"]),
        size=row["size"],
        error=row["error"],
        attestation=json.loads(row["attestation"]) if row["attestation"] else None,
    )


def _sbom_from_row(row: sqlite3.Row) -> SbomRecord:
    return SbomRecord(
        uuid=row["uuid"],
        path=row["path"],
        media_type=row["media_type"],
        sha256=row["sha256"],
        format=row["format"],
        valid=bool(row["valid"]),
    )


_SBOM_COLUMNS = "uuid, wheel_url, path, media_type, sha256, format, valid"


def get_release(conn: sqlite3.Connection, name: str, version: str) -> ReleaseRecord | None:
    row = conn.execute(
        "SELECT name, version, created, info FROM releases WHERE name = ? AND version = ?", (name, version)
    ).fetchone()
    if row is None:
        return None
    wheels = {
        w["url"]: _wheel_from_row(w)
        for w in conn.execute("SELECT * FROM wheels WHERE name = ? AND version = ? ORDER BY filename", (name, version))
    }
    for s in conn.execute(
        f"SELECT {_SBOM_COLUMNS} FROM sboms WHERE name = ? AND version = ? ORDER BY path", (name, version)
    ):
        wheel = wheels.get(s["wheel_url"])
        if wheel is not None:
            wheel.sboms.append(_sbom_from_row(s))
    return ReleaseRecord(
        name=row["name"],
        version=row["version"],
        created=row["created"],
        info=json.loads(row["info"]),
        wheels=list(wheels.values()),
    )


def release_exists(conn: sqlite3.Connection, name: str, version: str) -> bool:
    row = conn.execute("SELECT 1 FROM releases WHERE name = ? AND version = ?", (name, version)).fetchone()
    return row is not None


def is_missing(conn: sqlite3.Connection, name: str, version: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM missing WHERE name = ? AND version = ? AND until > ?", (name, version, int(time.time()))
    ).fetchone()
    return row is not None


def get_entity(conn: sqlite3.Connection, uuid: str) -> Entity | None:
    row = conn.execute("SELECT uuid, kind, name, version, wheel_url FROM entities WHERE uuid = ?", (uuid,)).fetchone()
    if row is None:
        return None
    return Entity(
        uuid=row["uuid"], kind=row["kind"], name=row["name"], version=row["version"], wheel_url=row["wheel_url"]
    )


def get_sbom_content(conn: sqlite3.Connection, uuid: str) -> tuple[bytes, str] | None:
    row = conn.execute("SELECT content, media_type FROM sboms WHERE uuid = ?", (uuid,)).fetchone()
    if row is None:
        return None
    return zlib.decompress(row["content"]), row["media_type"]


# Listing families beyond the SBOM-format ones ('' = every release with an SBOM).
ALL_PRODUCTS = "*products"
ALL_RELEASES = "*releases"
CATALOG_VERSION_KEY = "catalog_version"


def _listing_page(conn: sqlite3.Connection, family: str, offset: int, limit: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT name, version, formats FROM listing WHERE family = ? AND pos > ? AND pos <= ? ORDER BY pos",
        (family, offset, offset + limit),
    ).fetchall()


def _listing_count(conn: sqlite3.Connection, family: str) -> int:
    row = conn.execute("SELECT max(pos) FROM listing WHERE family = ?", (family,)).fetchone()
    return int(row[0] or 0)


def list_products(conn: sqlite3.Connection, offset: int, limit: int) -> list[str]:
    return [r["name"] for r in _listing_page(conn, ALL_PRODUCTS, offset, limit)]


def count_products(conn: sqlite3.Connection) -> int:
    return _listing_count(conn, ALL_PRODUCTS)


def product_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM releases WHERE name = ? LIMIT 1", (name,)).fetchone() is not None


def list_release_keys(conn: sqlite3.Connection, offset: int, limit: int) -> list[tuple[str, str]]:
    return [(r["name"], r["version"]) for r in _listing_page(conn, ALL_RELEASES, offset, limit)]


def count_listed_releases(conn: sqlite3.Connection) -> int:
    return _listing_count(conn, ALL_RELEASES)


def product_release_versions(conn: sqlite3.Connection, name: str) -> list[str]:
    rows = conn.execute(
        "SELECT version FROM releases WHERE name = ? ORDER BY created DESC, version DESC", (name,)
    ).fetchall()
    return [r["version"] for r in rows]


def packages_with_sbom(
    conn: sqlite3.Connection, family: str | None, offset: int, limit: int
) -> list[tuple[str, str, list[str]]]:
    rows = _listing_page(conn, family or "", offset, limit)
    return [(r["name"], r["version"], r["formats"].split(",") if r["formats"] else []) for r in rows]


def count_packages_with_sbom(conn: sqlite3.Connection, family: str | None) -> int:
    return _listing_count(conn, family or "")


def sbom_families(conn: sqlite3.Connection) -> list[str]:
    return [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT family FROM listing WHERE family NOT IN ('', ?, ?) ORDER BY family",
            (ALL_PRODUCTS, ALL_RELEASES),
        )
    ]


def rebuild_listing(conn: sqlite3.Connection) -> int:
    """Recompute the name-ordered browse positions for /packages.

    O(n) in releases with an SBOM, a small fraction of the catalog; run by the worker
    when the SBOM set changes, never per request. /products and /productReleases are
    appended to by save_release and not touched here.
    """
    begin(conn)
    try:
        conn.execute("DELETE FROM listing WHERE family NOT IN (?, ?)", (ALL_PRODUCTS, ALL_RELEASES))
        conn.execute(
            """
            INSERT INTO listing (family, pos, name, version, formats)
            SELECT '', row_number() OVER (ORDER BY name, version), name, version, formats
            FROM (SELECT name, version, group_concat(DISTINCT format) AS formats FROM sboms GROUP BY name, version)
            """
        )
        conn.execute(
            """
            INSERT INTO listing (family, pos, name, version, formats)
            SELECT f.family, row_number() OVER (PARTITION BY f.family ORDER BY f.name, f.version),
                   f.name, f.version, a.formats
            FROM (SELECT DISTINCT family, name, version FROM sboms) f
            JOIN listing a ON a.family = '' AND a.name = f.name AND a.version = f.version
            """
        )
        n = int(conn.execute("SELECT count(*) FROM listing WHERE family = ''").fetchone()[0])
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return n


def rebuild_catalog_listing(conn: sqlite3.Connection) -> None:
    """Lay out /products and /productReleases in discovery order, the order save_release appends in.

    O(n) in releases. Only run when migrating a store; the caller holds the transaction.
    """
    conn.execute("DELETE FROM listing WHERE family IN (?, ?)", (ALL_PRODUCTS, ALL_RELEASES))
    conn.execute(
        """
        INSERT INTO listing (family, pos, name, version, formats)
        SELECT ?, row_number() OVER (ORDER BY min(first_seen), name), name, '', ''
        FROM releases GROUP BY name
        """,
        (ALL_PRODUCTS,),
    )
    conn.execute(
        """
        INSERT INTO listing (family, pos, name, version, formats)
        SELECT ?, row_number() OVER (ORDER BY first_seen, name, version), name, version, ''
        FROM releases
        """,
        (ALL_RELEASES,),
    )


def _append_listing(conn: sqlite3.Connection, family: str, name: str, version: str) -> None:
    conn.execute(
        """
        INSERT INTO listing (family, pos, name, version, formats)
        SELECT ?, coalesce(max(pos), 0) + 1, ?, ?, '' FROM listing WHERE family = ?
        """,
        (family, name, version, family),
    )


def catalog_version(conn: sqlite3.Connection) -> int:
    """Bumped by save_release whenever a release's SBOM formats change, i.e. the SBOM listings would."""
    return int(get_meta(conn, CATALOG_VERSION_KEY) or 0)


def all_product_names(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT name FROM releases ORDER BY name")]


def all_release_keys(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return [(r[0], r[1]) for r in conn.execute("SELECT name, version FROM releases ORDER BY name, version")]


# --- sitemap ---

# Google takes up to 50k URLs per sitemap; stay well under so each shard is a cheap range read.
SITEMAP_SHARD_SIZE = 10_000


def sitemap_shards(conn: sqlite3.Connection) -> list[tuple[int, int]]:
    """(shard, lastmod) for every shard with a URL in it. One row per shard, ~70 at 700k URLs."""
    return [
        (r[0], r[1]) for r in conn.execute("SELECT shard, lastmod FROM sitemap_shards WHERE urls > 0 ORDER BY shard")
    ]


def sitemap_shard(conn: sqlite3.Connection, shard: int) -> list[tuple[str, str, int]]:
    """(name, version, lastmod) of one shard's URLs, a range read over the covering index."""
    return [
        (r[0], r[1], r[2])
        for r in conn.execute(
            "SELECT name, version, lastmod FROM sitemap WHERE shard = ? ORDER BY name, version", (shard,)
        )
    ]


def _listed(release: ReleaseRecord) -> bool:
    """Whether the release's package page answers 200 at its own URL, i.e. belongs in the sitemap."""
    return release.has_sbom and canonicalize_name(release.name) == release.name


def _page_digest(release: ReleaseRecord) -> str:
    """Hash of everything stored for a release that its package page shows."""
    wheels = [
        {
            "url": w.url,
            "filename": w.filename,
            "digests": w.digests,
            "size": w.size,
            "error": w.error,
            "attestation": w.attestation,
            "sboms": sorted((s.uuid, s.path, s.media_type, s.sha256, s.format, s.valid) for s in w.sboms),
        }
        for w in sorted(release.wheels, key=lambda w: w.url)
    ]
    page = {"created": release.created, "info": release.info, "wheels": wheels}
    return hashlib.sha256(json.dumps(page, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _touch_shard(conn: sqlite3.Connection, shard: int, now: int) -> None:
    conn.execute("UPDATE sitemap_shards SET lastmod = max(lastmod, ?) WHERE shard = ?", (now, shard))


def _update_sitemap(conn: sqlite3.Connection, release: ReleaseRecord, now: int) -> None:
    """Keep one release's sitemap entry current. Touches only the shard the release is in."""
    name, version = release.name, release.version
    row = conn.execute("SELECT shard, digest FROM sitemap WHERE name = ? AND version = ?", (name, version)).fetchone()
    if not _listed(release):
        if row is not None:
            conn.execute("DELETE FROM sitemap WHERE name = ? AND version = ?", (name, version))
            conn.execute("UPDATE sitemap_shards SET urls = urls - 1 WHERE shard = ?", (row["shard"],))
            _touch_shard(conn, row["shard"], now)
        return
    digest = _page_digest(release)
    if row is None:
        # New URLs only ever go to the last shard, so no existing shard's contents move.
        last = conn.execute("SELECT shard, assigned FROM sitemap_shards ORDER BY shard DESC LIMIT 1").fetchone()
        if last is None:
            shard = 0
        elif last["assigned"] < SITEMAP_SHARD_SIZE:
            shard = int(last["shard"])
        else:
            shard = int(last["shard"]) + 1
        conn.execute(
            "INSERT INTO sitemap (name, version, shard, lastmod, digest) VALUES (?, ?, ?, ?, ?)",
            (name, version, shard, now, digest),
        )
        conn.execute(
            """
            INSERT INTO sitemap_shards (shard, assigned, urls, lastmod) VALUES (?, 1, 1, ?)
            ON CONFLICT (shard) DO UPDATE SET
                assigned = assigned + 1, urls = urls + 1, lastmod = max(lastmod, excluded.lastmod)
            """,
            (shard, now),
        )
    elif row["digest"] != digest:
        if row["digest"] is None:
            # Backfilled by the migration with lastmod = resolved_at; record what the page shows now.
            conn.execute("UPDATE sitemap SET digest = ? WHERE name = ? AND version = ?", (digest, name, version))
        else:
            conn.execute(
                "UPDATE sitemap SET digest = ?, lastmod = ? WHERE name = ? AND version = ?",
                (digest, now, name, version),
            )
            _touch_shard(conn, row["shard"], now)


def _touch_sitemap_for_sbom(conn: sqlite3.Connection, sha256: str, now: int) -> None:
    """Move lastmod of every listed release that ships an SBOM with this hash (its scan findings changed)."""
    keys = conn.execute("SELECT DISTINCT name, version FROM sboms WHERE sha256 = ?", (sha256,)).fetchall()
    for name, version in keys:
        row = conn.execute("SELECT shard FROM sitemap WHERE name = ? AND version = ?", (name, version)).fetchone()
        if row is not None:
            conn.execute("UPDATE sitemap SET lastmod = ? WHERE name = ? AND version = ?", (now, name, version))
            _touch_shard(conn, row["shard"], now)


def rebuild_sitemap(conn: sqlite3.Connection) -> None:
    """Lay out the sitemap from scratch: releases in discovery order, SITEMAP_SHARD_SIZE per shard.

    O(n) in releases. Only run when migrating a store; the caller holds the transaction.
    lastmod starts at resolved_at, the best record there is of when the page last changed.
    """
    conn.create_function("canonical_name", 1, lambda n: str(canonicalize_name(n)), deterministic=True)
    conn.execute("DELETE FROM sitemap")
    conn.execute("DELETE FROM sitemap_shards")
    conn.execute(
        """
        INSERT INTO sitemap (name, version, shard, lastmod, digest)
        SELECT name, version, (row_number() OVER (ORDER BY first_seen, name, version) - 1) / ?, resolved_at, NULL
        FROM releases WHERE has_sbom = 1 AND canonical_name(name) = name
        """,
        (SITEMAP_SHARD_SIZE,),
    )
    conn.execute(
        """
        INSERT INTO sitemap_shards (shard, assigned, urls, lastmod)
        SELECT shard, count(*), count(*), max(lastmod) FROM sitemap GROUP BY shard
        """
    )


# --- stats ---


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    counts: dict[str, dict[str, int]] = {}
    for kind, key, n in conn.execute("SELECT kind, key, n FROM counters WHERE n != 0"):
        counts.setdefault(kind, {})[key] = int(n)
    releases = counts.get("releases", {})
    pkg_total = releases.get("total", 0)
    pkg_with_sbom = releases.get("with_sbom", 0)
    wheels = counts.get("wheels", {})
    wheels_with = wheels.get("with_sbom", 0)
    wheels_without = wheels.get("without_sbom", 0)
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
        "sbom_formats": counts.get("sbom_format", {}),
        "sbom_validation": counts.get("sbom_validation", {}),
        "sbom_encodings": counts.get("sbom_encoding", {}),
        "attestations": counts.get("attestation", {}),
        "attestation_publishers": counts.get("publisher", {}),
    }


DAY = 86400
TIMESERIES_DAYS = 30


def stats_timeseries(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    since = (int(time.time()) // DAY - TIMESERIES_DAYS) * DAY
    days: dict[int, dict[str, Any]] = {}
    for day, kind, key, n in conn.execute(
        "SELECT day, kind, key, n FROM daily_counters WHERE day >= ? AND n != 0 ORDER BY day", (since,)
    ):
        entry = days.setdefault(
            int(day),
            {"timestamp": int(day), "packages": {"new_explored": 0, "new_with_sbom": 0}, "sbom_formats": {}},
        )
        if kind == "format":
            entry["sbom_formats"][key] = int(n)
        else:
            entry["packages"]["new_" + kind] = int(n)
    return [d for d in days.values() if d["packages"]["new_explored"]]


def invalid_sboms(conn: sqlite3.Connection) -> list[dict[str, str]]:
    return [
        {
            "package": r["name"],
            "version": r["version"],
            "sbom_path": r["path"],
            "wheel_url": r["wheel_url"],
            "format": r["format"],
        }
        for r in conn.execute(
            "SELECT name, version, path, wheel_url, format FROM sboms WHERE valid = 0 ORDER BY name, version, path"
        )
    ]


def usage_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    def top(kind: str, n: int) -> list[tuple[str, int]]:
        return [
            (r[0], r[1])
            for r in conn.execute(
                "SELECT key, count FROM usage_counts WHERE kind = ? ORDER BY count DESC, key LIMIT ?", (kind, n)
            )
        ]

    top_packages = [{"package": k, "queries": c} for k, c in top("package", 20)]
    total_row = conn.execute("SELECT coalesce(sum(count), 0) FROM usage_counts WHERE kind = 'package'").fetchone()
    qualifier_row = conn.execute(
        "SELECT coalesce(sum(count), 0) FROM usage_counts WHERE kind = 'qualified_queries'"
    ).fetchone()
    since = (int(time.time()) // DAY - TIMESERIES_DAYS) * DAY
    daily = [
        {"timestamp": r[0], "queries": r[1]}
        for r in conn.execute("SELECT day, queries FROM usage_daily WHERE day >= ? ORDER BY day", (since,))
    ]
    recent = [json.loads(r[0]) for r in conn.execute("SELECT entry FROM usage_recent ORDER BY id DESC LIMIT 100")]
    return {
        "total_queries": int(total_row[0]),
        "qualifier_queries": int(qualifier_row[0]),
        "top_packages": top_packages,
        "qualifiers": {"os": dict(top("os", 10)), "arch": dict(top("arch", 10))},
        "endpoints": dict(top("endpoint", 20)),
        "recent": recent,
        "daily_queries": daily,
    }


# --- counters ---

Totals = Counter[tuple[str, str]]
Daily = Counter[tuple[int, str, str]]


def _contribution(conn: sqlite3.Connection, name: str, version: str) -> tuple[Totals, Daily]:
    """What one release's stored rows add to `counters` and `daily_counters`. Index reads only."""
    totals: Totals = Counter()
    daily: Daily = Counter()
    row = conn.execute(
        "SELECT has_sbom, first_seen FROM releases WHERE name = ? AND version = ?", (name, version)
    ).fetchone()
    if row is None:
        return totals, daily
    day = int(row["first_seen"]) // DAY * DAY
    totals["releases", "total"] += 1
    totals["releases", "with_sbom"] += int(row["has_sbom"])
    daily[day, "explored", ""] += 1
    daily[day, "with_sbom", ""] += int(row["has_sbom"])
    for has_sbom, status, kind in conn.execute(
        """
        SELECT has_sbom, json_extract(attestation, '$.status'), json_extract(attestation, '$.publisher_kind')
        FROM wheels WHERE name = ? AND version = ?
        """,
        (name, version),
    ):
        totals["wheels", "with_sbom" if has_sbom else "without_sbom"] += 1
        if status:
            totals["attestation", status] += 1
        if kind:
            totals["publisher", kind] += 1
    for fmt, valid, media_type in conn.execute(
        "SELECT format, valid, media_type FROM sboms WHERE name = ? AND version = ?", (name, version)
    ):
        totals["sbom_format", fmt] += 1
        totals["sbom_validation", "valid" if valid else "invalid"] += 1
        totals["sbom_encoding", media_type] += 1
        daily[day, "format", fmt] += 1
    return totals, daily


def _apply_counts(conn: sqlite3.Connection, totals: Totals, daily: Daily) -> None:
    conn.executemany(
        "INSERT INTO counters (kind, key, n) VALUES (?, ?, ?) ON CONFLICT (kind, key) DO UPDATE SET n = n + excluded.n",
        [(kind, key, n) for (kind, key), n in totals.items() if n],
    )
    conn.executemany(
        """
        INSERT INTO daily_counters (day, kind, key, n) VALUES (?, ?, ?, ?)
        ON CONFLICT (day, kind, key) DO UPDATE SET n = n + excluded.n
        """,
        [(day, kind, key, n) for (day, kind, key), n in daily.items() if n],
    )


# Every counter recomputed from the tables, for migration. Mirrors _contribution.
_RECOUNT = (
    "DELETE FROM counters",
    "DELETE FROM daily_counters",
    "INSERT INTO counters SELECT 'releases', 'total', count(*) FROM releases",
    "INSERT INTO counters SELECT 'releases', 'with_sbom', coalesce(sum(has_sbom), 0) FROM releases",
    """
    INSERT INTO counters
    SELECT 'wheels', CASE WHEN has_sbom THEN 'with_sbom' ELSE 'without_sbom' END, count(*) FROM wheels GROUP BY 2
    """,
    "INSERT INTO counters SELECT 'sbom_format', format, count(*) FROM sboms GROUP BY format",
    """
    INSERT INTO counters
    SELECT 'sbom_validation', CASE WHEN valid THEN 'valid' ELSE 'invalid' END, count(*) FROM sboms GROUP BY 2
    """,
    "INSERT INTO counters SELECT 'sbom_encoding', media_type, count(*) FROM sboms GROUP BY media_type",
    """
    INSERT INTO counters SELECT 'attestation', s, count(*)
    FROM (SELECT json_extract(attestation, '$.status') AS s FROM wheels)
    WHERE s IS NOT NULL AND s != '' GROUP BY s
    """,
    """
    INSERT INTO counters SELECT 'publisher', k, count(*)
    FROM (SELECT json_extract(attestation, '$.publisher_kind') AS k FROM wheels)
    WHERE k IS NOT NULL AND k != '' GROUP BY k
    """,
    f"""
    INSERT INTO daily_counters SELECT first_seen / {DAY} * {DAY}, 'explored', '', count(*) FROM releases GROUP BY 1
    """,
    f"""
    INSERT INTO daily_counters
    SELECT first_seen / {DAY} * {DAY}, 'with_sbom', '', sum(has_sbom) FROM releases GROUP BY 1
    """,
    f"""
    INSERT INTO daily_counters SELECT r.first_seen / {DAY} * {DAY}, 'format', s.format, count(*)
    FROM sboms s JOIN releases r ON r.name = s.name AND r.version = s.version GROUP BY 1, 3
    """,
)


def recount(conn: sqlite3.Connection) -> None:
    """Recompute every counter from the tables. O(n) in the whole store; the caller holds the transaction."""
    for statement in _RECOUNT:
        conn.execute(statement)


# --- writes ---


def save_release(conn: sqlite3.Connection, release: ReleaseRecord) -> None:
    """Replace everything stored for one release in a single transaction."""
    now = int(time.time())
    name, version = release.name, release.version
    new_formats = sorted({(s.format) for w in release.wheels for s in w.sboms})
    begin(conn)
    try:
        existed = release_exists(conn, name, version)
        new_product = not existed and not product_exists(conn, name)
        old_totals, old_daily = _contribution(conn, name, version)
        old_formats = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT format FROM sboms WHERE name = ? AND version = ? ORDER BY format", (name, version)
            )
        ]
        if old_formats != new_formats:
            conn.execute(
                """
                INSERT INTO meta (key, value) VALUES (?, '1')
                ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
                """,
                (CATALOG_VERSION_KEY,),
            )
        conn.execute(
            """
            INSERT INTO releases (name, version, created, first_seen, resolved_at, has_sbom, info)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (name, version) DO UPDATE SET
                created = excluded.created, resolved_at = excluded.resolved_at,
                has_sbom = excluded.has_sbom, info = excluded.info
            """,
            (name, version, release.created, now, now, int(release.has_sbom), json.dumps(release.info)),
        )
        conn.execute("DELETE FROM wheels WHERE name = ? AND version = ?", (name, version))
        conn.execute("DELETE FROM sboms WHERE name = ? AND version = ?", (name, version))
        conn.execute("DELETE FROM missing WHERE name = ? AND version = ?", (name, version))
        entities: list[tuple[str, str, str, str | None, str | None]] = [
            (product_uuid(name), "product", name, None, None),
            (product_release_uuid(name, version), "product_release", name, version, None),
        ]
        for w in release.wheels:
            conn.execute(
                """
                INSERT OR REPLACE INTO wheels
                    (url, name, version, filename, digests, size, has_sbom, error, attestation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    w.url,
                    name,
                    version,
                    w.filename,
                    json.dumps(w.digests),
                    w.size,
                    int(w.has_sbom),
                    w.error,
                    json.dumps(w.attestation) if w.attestation is not None else None,
                ),
            )
            entities.append((component_uuid(w.filename), "component", name, version, w.url))
            entities.append((component_release_uuid(w.url), "component_release", name, version, w.url))
            for s in w.sboms:
                if s.content is None:
                    raise ValueError(f"SBOM {s.path} has no content to store")
                conn.execute(
                    """
                    INSERT OR REPLACE INTO sboms
                        (uuid, wheel_url, name, version, path, media_type, sha256, format, family, valid, content)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        s.uuid,
                        w.url,
                        name,
                        version,
                        s.path,
                        s.media_type,
                        s.sha256,
                        s.format,
                        s.family,
                        int(s.valid),
                        zlib.compress(s.content.encode(), 6),
                    ),
                )
                entities.append((artifact_uuid(w.url, s.path), "artifact", name, version, w.url))
        conn.executemany("INSERT OR REPLACE INTO entities VALUES (?, ?, ?, ?, ?)", entities)
        if new_product:
            _append_listing(conn, ALL_PRODUCTS, name, "")
        if not existed:
            _append_listing(conn, ALL_RELEASES, name, version)
        _update_sitemap(conn, release, now)
        new_totals, new_daily = _contribution(conn, name, version)
        new_totals.subtract(old_totals)
        new_daily.subtract(old_daily)
        _apply_counts(conn, new_totals, new_daily)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def get_stored_sbom_contents(conn: sqlite3.Connection, wheel_url: str) -> dict[str, str]:
    """path -> content for a wheel already ingested (used to skip re-downloading immutable wheels)."""
    return {
        r["path"]: zlib.decompress(r["content"]).decode()
        for r in conn.execute("SELECT path, content FROM sboms WHERE wheel_url = ?", (wheel_url,))
    }


def mark_missing(conn: sqlite3.Connection, name: str, version: str, ttl: int = MISSING_TTL) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO missing (name, version, until) VALUES (?, ?, ?)",
        (name, version, int(time.time()) + ttl),
    )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row[0])


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


# --- vulnerability scans ---


def osv_scans(conn: sqlite3.Connection, sha256s: list[str]) -> dict[str, dict[str, Any]]:
    """sha256 -> latest scan, for the SBOMs on one page. One primary-key lookup each."""
    out: dict[str, dict[str, Any]] = {}
    for sha in dict.fromkeys(sha256s):
        row = conn.execute(
            "SELECT scanned_at, scanner, error, findings FROM osv_scans WHERE sha256 = ?", (sha,)
        ).fetchone()
        if row is not None:
            out[sha] = {
                "scanned_at": int(row["scanned_at"]),
                "scanner": row["scanner"],
                "error": row["error"],
                "findings": json.loads(zlib.decompress(row["findings"])),
            }
    return out


def sboms_due_for_scan(conn: sqlite3.Connection, scanned_before: int, limit: int) -> list[str]:
    """Distinct SBOM hashes never scanned or last scanned before `scanned_before`, never-scanned first.

    O(n) in SBOMs over two indexes; run by pypi-tea-osv, never per request.
    """
    return [
        r[0]
        for r in conn.execute(
            """
            SELECT s.sha256 FROM (SELECT DISTINCT sha256 FROM sboms) s
            LEFT JOIN osv_scans o ON o.sha256 = s.sha256
            WHERE o.sha256 IS NULL OR o.scanned_at < ?
            ORDER BY coalesce(o.scanned_at, 0), s.sha256
            LIMIT ?
            """,
            (scanned_before, limit),
        )
    ]


def sbom_for_scan(conn: sqlite3.Connection, sha256: str) -> tuple[bytes, str] | None:
    """Content and media type of one stored SBOM with this hash."""
    row = conn.execute("SELECT content, media_type FROM sboms WHERE sha256 = ? LIMIT 1", (sha256,)).fetchone()
    if row is None:
        return None
    return zlib.decompress(row["content"]), row["media_type"]


def save_osv_scans(
    conn: sqlite3.Connection, scanner: str, results: list[tuple[str, str | None, list[dict[str, Any]]]]
) -> None:
    """Store (sha256, error, findings) for a batch of scans in one transaction.

    A scan whose result differs from the last one changes what the package pages
    show, so it moves their sitemap lastmod; a rescan that finds the same doesn't.
    """
    now = int(time.time())
    rows = []
    for sha, error, findings in results:
        worst = findings[0]["severity"] if findings else None
        payload = zlib.compress(json.dumps(findings, separators=(",", ":")).encode(), 6)
        rows.append((sha, now, scanner, error, len(findings), worst, payload))
    begin(conn)
    try:
        for sha, _, _, error, _, _, payload in rows:
            old = conn.execute("SELECT error, findings FROM osv_scans WHERE sha256 = ?", (sha,)).fetchone()
            if old is None or old["error"] != error or bytes(old["findings"]) != payload:
                _touch_sitemap_for_sbom(conn, sha, now)
        conn.executemany("INSERT OR REPLACE INTO osv_scans VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def prune_osv_scans(conn: sqlite3.Connection) -> int:
    """Drop scans of SBOMs no longer stored (a re-resolve changed a wheel's SBOM)."""
    cur = conn.execute("DELETE FROM osv_scans WHERE sha256 NOT IN (SELECT sha256 FROM sboms)")
    return cur.rowcount

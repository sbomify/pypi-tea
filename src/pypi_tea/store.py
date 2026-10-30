"""Queries over the SQLite store.

Every read here is an indexed lookup or an index-ordered range scan; nothing on
the read path sorts or scans a whole table. Writes happen in the worker, one
release per transaction.
"""

import json
import sqlite3
import time
import zlib
from typing import Any

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


def list_products(conn: sqlite3.Connection, offset: int, limit: int) -> list[str]:
    rows = conn.execute("SELECT DISTINCT name FROM releases ORDER BY name LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    return [r["name"] for r in rows]


def count_products(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT count(DISTINCT name) FROM releases").fetchone()[0])


def product_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM releases WHERE name = ? LIMIT 1", (name,)).fetchone() is not None


def list_release_keys(conn: sqlite3.Connection, offset: int, limit: int) -> list[tuple[str, str]]:
    rows = conn.execute(
        "SELECT name, version FROM releases ORDER BY name, version LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    return [(r["name"], r["version"]) for r in rows]


def count_releases(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT count(*) FROM releases").fetchone()[0])


def product_release_versions(conn: sqlite3.Connection, name: str) -> list[str]:
    rows = conn.execute(
        "SELECT version FROM releases WHERE name = ? ORDER BY created DESC, version DESC", (name,)
    ).fetchall()
    return [r["version"] for r in rows]


def packages_with_sbom(
    conn: sqlite3.Connection, family: str | None, offset: int, limit: int
) -> list[tuple[str, str, list[str]]]:
    rows = conn.execute(
        "SELECT name, version, formats FROM listing WHERE family = ? AND pos > ? AND pos <= ? ORDER BY pos",
        (family or "", offset, offset + limit),
    ).fetchall()
    return [(r["name"], r["version"], r["formats"].split(",") if r["formats"] else []) for r in rows]


def count_packages_with_sbom(conn: sqlite3.Connection, family: str | None) -> int:
    row = conn.execute("SELECT max(pos) FROM listing WHERE family = ?", (family or "",)).fetchone()
    return int(row[0] or 0)


def sbom_families(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT family FROM listing WHERE family != '' ORDER BY family")]


def rebuild_listing(conn: sqlite3.Connection) -> int:
    """Recompute browse positions for releases with SBOMs. O(n); run by the worker, not per request."""
    begin(conn)
    try:
        conn.execute("DELETE FROM listing")
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


def last_resolved_at(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT max(resolved_at) FROM releases").fetchone()
    return int(row[0] or 0)


def all_product_names(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT name FROM releases ORDER BY name")]


def all_release_keys(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return [(r[0], r[1]) for r in conn.execute("SELECT name, version FROM releases ORDER BY name, version")]


# --- stats ---


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    pkg_total = count_releases(conn)
    pkg_with_sbom = int(conn.execute("SELECT count(*) FROM releases WHERE has_sbom = 1").fetchone()[0])
    wheel_rows = {r[0]: r[1] for r in conn.execute("SELECT has_sbom, count(*) FROM wheels GROUP BY has_sbom")}
    wheels_with = int(wheel_rows.get(1, 0))
    wheels_without = int(wheel_rows.get(0, 0))
    wheels_total = wheels_with + wheels_without

    formats = {r[0]: r[1] for r in conn.execute("SELECT format, count(*) FROM sboms GROUP BY format")}
    validation: dict[str, int] = {}
    for valid, n in conn.execute("SELECT valid, count(*) FROM sboms GROUP BY valid"):
        validation["valid" if valid else "invalid"] = n
    encodings = {r[0]: r[1] for r in conn.execute("SELECT media_type, count(*) FROM sboms GROUP BY media_type")}
    attestations: dict[str, int] = {}
    publishers: dict[str, int] = {}
    for status, kind, n in conn.execute(
        """
        SELECT json_extract(attestation, '$.status'), json_extract(attestation, '$.publisher_kind'), count(*)
        FROM wheels WHERE attestation IS NOT NULL GROUP BY 1, 2
        """
    ):
        if status:
            attestations[status] = attestations.get(status, 0) + n
        if kind:
            publishers[kind] = publishers.get(kind, 0) + n

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
        "sbom_formats": formats,
        "sbom_validation": validation,
        "sbom_encodings": encodings,
        "attestations": attestations,
        "attestation_publishers": publishers,
    }


DAY = 86400
TIMESERIES_DAYS = 30


def stats_timeseries(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    since = (int(time.time()) // DAY - TIMESERIES_DAYS) * DAY
    series: list[dict[str, Any]] = []
    rows = conn.execute(
        """
        SELECT first_seen / ? * ? AS day, count(*) AS explored, sum(has_sbom) AS with_sbom
        FROM releases WHERE first_seen >= ? GROUP BY day ORDER BY day
        """,
        (DAY, DAY, since),
    ).fetchall()
    formats_by_day: dict[int, dict[str, int]] = {}
    for day, fmt, n in conn.execute(
        """
        SELECT r.first_seen / ? * ? AS day, s.format, count(*)
        FROM sboms s JOIN releases r ON r.name = s.name AND r.version = s.version
        WHERE r.first_seen >= ? GROUP BY day, s.format
        """,
        (DAY, DAY, since),
    ):
        formats_by_day.setdefault(int(day), {})[fmt] = n
    for r in rows:
        day = int(r["day"])
        series.append(
            {
                "timestamp": day,
                "packages": {"new_explored": r["explored"], "new_with_sbom": r["with_sbom"] or 0},
                "sbom_formats": formats_by_day.get(day, {}),
            }
        )
    return series


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


# --- writes ---


def save_release(conn: sqlite3.Connection, release: ReleaseRecord) -> None:
    """Replace everything stored for one release in a single transaction."""
    now = int(time.time())
    name, version = release.name, release.version
    begin(conn)
    try:
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

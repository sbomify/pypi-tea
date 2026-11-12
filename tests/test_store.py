"""Counters and catalog listings that save_release keeps current, and the migration that seeds them."""

import sqlite3

import pytest

from pypi_tea import db, store
from pypi_tea.models import ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.services.uuids import artifact_uuid


def _release(name: str, version: str, sboms: list[tuple[str, bool]], attested: bool = False) -> ReleaseRecord:
    """One wheel with an SBOM per (format, valid) pair, plus one wheel without."""
    wheels = []
    for i, (fmt, valid) in enumerate(sboms):
        url = f"https://files.example.com/{name}-{version}-{i}.whl"
        path = f"{name}-{version}.dist-info/sboms/{i}.json"
        wheels.append(
            WheelRecord(
                url=url,
                filename=f"{name}-{version}-{i}.whl",
                digests={"sha256": "0" * 64},
                size=1,
                sboms=[SbomRecord(artifact_uuid(url, path), path, "application/json", "0" * 64, fmt, valid, "{}")],
                attestation={"status": "verified", "publisher_kind": "GitHub"} if attested else None,
            )
        )
    wheels.append(
        WheelRecord(
            url=f"https://files.example.com/{name}-{version}-bare.whl",
            filename=f"{name}-{version}-bare.whl",
            digests={},
            size=1,
            attestation={"status": "not_available"},
        )
    )
    return ReleaseRecord(name=name, version=version, created=None, info={}, wheels=wheels)


def _counts(conn: sqlite3.Connection) -> tuple[dict[tuple[str, str], int], dict[tuple[int, str, str], int]]:
    totals = {(k, key): n for k, key, n in conn.execute("SELECT kind, key, n FROM counters WHERE n != 0")}
    daily = {(d, k, key): n for d, k, key, n in conn.execute("SELECT * FROM daily_counters WHERE n != 0")}
    return totals, daily


def _listing(conn: sqlite3.Connection, family: str) -> list[tuple[str, str]]:
    return [
        (r[0], r[1]) for r in conn.execute("SELECT name, version FROM listing WHERE family = ? ORDER BY pos", (family,))
    ]


def _save_some(conn: sqlite3.Connection) -> None:
    store.save_release(conn, _release("b", "1", [("CycloneDX/1.6", True)], attested=True))
    store.save_release(conn, _release("a", "1", []))
    store.save_release(conn, _release("b", "2", [("SPDX/2.3", False), ("CycloneDX/1.5", True)]))
    # Re-resolves: one SBOM set shrinks, one is unchanged.
    store.save_release(conn, _release("b", "2", [("SPDX/2.3", True)]))
    store.save_release(conn, _release("b", "1", [("CycloneDX/1.6", True)], attested=True))


def test_incremental_counters_match_a_recount(database: str) -> None:
    conn = db.connect(database)
    _save_some(conn)
    incremental = _counts(conn)
    db.begin(conn)
    store.recount(conn)
    conn.execute("COMMIT")
    assert _counts(conn) == incremental

    stats = store.stats(conn)
    assert stats["packages"]["total_explored"] == 3
    assert stats["packages"]["with_sbom"] == 2
    assert stats["wheels"] == {"total_checked": 5, "with_sbom": 2, "without_sbom": 3, "sbom_percentage": 40.0}
    assert stats["sbom_formats"] == {"CycloneDX/1.6": 1, "SPDX/2.3": 1}
    assert stats["sbom_validation"] == {"valid": 2}
    assert stats["attestations"] == {"verified": 1, "not_available": 3}
    assert stats["attestation_publishers"] == {"GitHub": 1}
    [day] = store.stats_timeseries(conn)
    assert day["packages"] == {"new_explored": 3, "new_with_sbom": 2}
    assert day["sbom_formats"] == {"CycloneDX/1.6": 1, "SPDX/2.3": 1}


def test_catalog_listings_are_appended_without_a_rebuild(database: str) -> None:
    conn = db.connect(database)
    _save_some(conn)
    assert _listing(conn, store.ALL_PRODUCTS) == [("b", ""), ("a", "")]
    assert _listing(conn, store.ALL_RELEASES) == [("b", "1"), ("a", "1"), ("b", "2")]
    assert store.count_products(conn) == 2
    assert store.list_release_keys(conn, 1, 10) == [("a", "1"), ("b", "2")]
    # The SBOM listing still needs the worker's rebuild, and leaves the catalog listings alone.
    assert store.count_packages_with_sbom(conn, None) == 0
    assert store.rebuild_listing(conn) == 2
    assert _listing(conn, "") == [("b", "1"), ("b", "2")]
    assert store.count_listed_releases(conn) == 3


def test_release_without_sbom_does_not_bump_catalog(database: str) -> None:
    conn = db.connect(database)
    store.save_release(conn, _release("a", "1", []))
    assert store.catalog_version(conn) == 0
    store.save_release(conn, _release("a", "2", [("CycloneDX/1.6", True)]))
    assert store.catalog_version(conn) == 1


def test_migration_seeds_counters_and_catalog_listings(database: str) -> None:
    conn = db.connect(database)
    _save_some(conn)
    # Saved within the same second; discovery order ties break by name, so spread them out.
    for offset, (name, version) in enumerate([("b", "1"), ("a", "1"), ("b", "2")]):
        conn.execute(
            "UPDATE releases SET first_seen = first_seen / 86400 * 86400 + ? WHERE name = ? AND version = ?",
            (offset, name, version),
        )
    expected = _counts(conn)
    # What a version 1 store looks like: no counters, a name-ordered catalog listing.
    conn.execute("DELETE FROM counters")
    conn.execute("DELETE FROM daily_counters")
    conn.execute("DELETE FROM listing")
    conn.execute("PRAGMA user_version=1")

    db.init_schema(database)

    assert _counts(conn) == expected
    assert _listing(conn, store.ALL_PRODUCTS) == [("b", ""), ("a", "")]
    assert _listing(conn, store.ALL_RELEASES) == [("b", "1"), ("a", "1"), ("b", "2")]
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


class _Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000

    def time(self) -> float:
        return float(self.now)


def _sitemap(conn: sqlite3.Connection) -> dict[int, list[tuple[str, str, int]]]:
    return {shard: store.sitemap_shard(conn, shard) for shard, _ in store.sitemap_shards(conn)}


def test_sitemap_shards_are_stable(database: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "SITEMAP_SHARD_SIZE", 2)
    clock = _Clock()
    monkeypatch.setattr(store, "time", clock)
    conn = db.connect(database)
    for name in ("a", "b", "c"):
        store.save_release(conn, _release(name, "1", [("CycloneDX/1.6", True)]))
    t0 = clock.now
    assert _sitemap(conn) == {0: [("a", "1", t0), ("b", "1", t0)], 1: [("c", "1", t0)]}

    # A new release sorts between a and b by name, but only the last shard takes it.
    clock.now += 100
    store.save_release(conn, _release("aa", "1", [("CycloneDX/1.6", True)]))
    assert store.sitemap_shards(conn) == [(0, t0), (1, t0 + 100)]
    assert _sitemap(conn)[1] == [("aa", "1", t0 + 100), ("c", "1", t0)]

    # Dropping out of the sitemap rewrites only the shard the release was in.
    clock.now += 100
    store.save_release(conn, _release("b", "1", []))
    assert store.sitemap_shards(conn) == [(0, t0 + 200), (1, t0 + 100)]
    assert _sitemap(conn)[0] == [("a", "1", t0)]

    # Shard 0 had two URLs assigned, so it isn't refilled; shard 1 is full, so a new one opens.
    clock.now += 100
    store.save_release(conn, _release("b", "1", [("CycloneDX/1.6", True)]))
    assert store.sitemap_shards(conn) == [(0, t0 + 200), (1, t0 + 100), (2, t0 + 300)]
    assert _sitemap(conn)[2] == [("b", "1", t0 + 300)]


def test_sitemap_lastmod_follows_page_content(database: str, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock()
    monkeypatch.setattr(store, "time", clock)
    conn = db.connect(database)
    store.save_release(conn, _release("a", "1", [("CycloneDX/1.6", True)]))
    t0 = clock.now
    # A re-resolve that finds the same (the weekly refresh) is not a change.
    clock.now += 100
    store.save_release(conn, _release("a", "1", [("CycloneDX/1.6", True)]))
    assert store.sitemap_shard(conn, 0) == [("a", "1", t0)]
    assert store.sitemap_shards(conn) == [(0, t0)]
    # A new attestation is.
    store.save_release(conn, _release("a", "1", [("CycloneDX/1.6", True)], attested=True))
    assert store.sitemap_shard(conn, 0) == [("a", "1", t0 + 100)]
    assert store.sitemap_shards(conn) == [(0, t0 + 100)]

    # So is a vulnerability scan with new findings, but not a rescan that finds the same.
    sha = "0" * 64
    clock.now += 100
    store.save_osv_scans(conn, "osv-scanner", [(sha, None, [])])
    assert store.sitemap_shard(conn, 0) == [("a", "1", t0 + 200)]
    clock.now += 100
    store.save_osv_scans(conn, "osv-scanner", [(sha, None, [])])
    assert store.sitemap_shard(conn, 0) == [("a", "1", t0 + 200)]
    store.save_osv_scans(conn, "osv-scanner", [(sha, None, [{"id": "CVE-1", "severity": "HIGH"}])])
    assert store.sitemap_shard(conn, 0) == [("a", "1", t0 + 300)]
    assert store.sitemap_shards(conn) == [(0, t0 + 300)]


def test_sitemap_lists_only_served_package_pages(database: str) -> None:
    conn = db.connect(database)
    store.save_release(conn, _release("a", "1", []))  # no SBOM: the page is a 404
    store.save_release(conn, _release("Ruamel.YAML", "1", [("CycloneDX/1.6", True)]))  # redirects
    store.save_release(conn, _release("ruamel-yaml", "1", [("CycloneDX/1.6", True)]))
    assert [(n, v) for n, v, _ in store.sitemap_shard(conn, 0)] == [("ruamel-yaml", "1")]
    assert len(store.sitemap_shards(conn)) == 1


def test_migration_lays_out_the_sitemap(database: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "SITEMAP_SHARD_SIZE", 2)
    conn = db.connect(database)
    for i, name in enumerate(("c", "a", "b", "d", "e")):
        store.save_release(conn, _release(name, "1", [("CycloneDX/1.6", True)] if name != "d" else []))
        conn.execute("UPDATE releases SET first_seen = ?, resolved_at = ? WHERE name = ?", (1000 + i, 2000 + i, name))
    # What a version 3 store looks like: no sitemap tables yet.
    conn.execute("DROP TABLE sitemap")
    conn.execute("DROP TABLE sitemap_shards")
    conn.execute("PRAGMA user_version=3")

    db.init_schema(database)

    assert _sitemap(conn) == {0: [("a", "1", 2001), ("c", "1", 2000)], 1: [("b", "1", 2002), ("e", "1", 2004)]}
    assert store.sitemap_shards(conn) == [(0, 2001), (1, 2004)]
    # The first save after the migration records the page digest without calling it a change.
    store.save_release(conn, _release("a", "1", [("CycloneDX/1.6", True)]))
    assert _sitemap(conn)[0][0] == ("a", "1", 2001)
    # Shard 1 is full, so new releases still start a new shard.
    store.save_release(conn, _release("f", "1", [("CycloneDX/1.6", True)]))
    assert [s for s, _ in store.sitemap_shards(conn)] == [0, 1, 2]

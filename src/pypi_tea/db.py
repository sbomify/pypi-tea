"""SQLite storage: schema, connections, and pragmas.

One database file holds everything. Wheels are immutable once published, so a
resolved release is stored permanently and never re-fetched to serve a read.
WAL mode lets every API process read concurrently while the worker writes.
"""

import sqlite3
import threading
from pathlib import Path

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS releases (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    created TEXT,
    first_seen INTEGER NOT NULL,
    resolved_at INTEGER NOT NULL,
    has_sbom INTEGER NOT NULL,
    info TEXT NOT NULL,
    PRIMARY KEY (name, version)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS releases_with_sbom ON releases (has_sbom, name, version);
CREATE INDEX IF NOT EXISTS releases_first_seen ON releases (first_seen);

CREATE TABLE IF NOT EXISTS wheels (
    url TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    filename TEXT NOT NULL,
    digests TEXT NOT NULL,
    size INTEGER,
    has_sbom INTEGER NOT NULL,
    error TEXT,
    attestation TEXT
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS wheels_release ON wheels (name, version);

CREATE TABLE IF NOT EXISTS sboms (
    uuid TEXT PRIMARY KEY,
    wheel_url TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    path TEXT NOT NULL,
    media_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    format TEXT NOT NULL,
    family TEXT NOT NULL,
    valid INTEGER NOT NULL,
    content BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS sboms_wheel ON sboms (wheel_url);
-- Covers the listing rebuild's GROUP BY, which would otherwise read every row's content.
CREATE INDEX IF NOT EXISTS sboms_release_format ON sboms (name, version, format);
CREATE INDEX IF NOT EXISTS sboms_family ON sboms (family, name, version);
-- Finds the SBOMs pypi-tea-osv hasn't scanned without reading their content.
CREATE INDEX IF NOT EXISTS sboms_sha256 ON sboms (sha256);

-- Latest osv-scanner result per SBOM, keyed by content hash: a re-resolved release
-- replaces its sboms rows but keeps its scans, and identical SBOMs are scanned once.
-- findings is zlib-compressed JSON, worst first; vulns and max_severity summarise it.
CREATE TABLE IF NOT EXISTS osv_scans (
    sha256 TEXT PRIMARY KEY,
    scanned_at INTEGER NOT NULL,
    scanner TEXT NOT NULL,
    error TEXT,
    vulns INTEGER NOT NULL,
    max_severity TEXT,
    findings BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS osv_scans_age ON osv_scans (scanned_at);

-- Deterministic UUID -> (kind, release, wheel) for every TEA entity.
CREATE TABLE IF NOT EXISTS entities (
    uuid TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    wheel_url TEXT
) WITHOUT ROWID;

-- Releases PyPI says do not exist; retried after `until`.
CREATE TABLE IF NOT EXISTS missing (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    until INTEGER NOT NULL,
    PRIMARY KEY (name, version)
) WITHOUT ROWID;

-- Work queue. version = '' means "check PyPI for this project's latest release".
-- priority: 0 = a client is waiting, 5 = migration / backfill, 9 = scheduled refresh.
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    priority INTEGER NOT NULL,
    enqueued_at INTEGER NOT NULL,
    not_before INTEGER NOT NULL DEFAULT 0,
    claimed_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    UNIQUE (name, version)
);
-- Matches the claim query's ORDER BY, so a claim walks the index instead of sorting the queue.
CREATE INDEX IF NOT EXISTS jobs_order ON jobs (priority, enqueued_at);

CREATE TABLE IF NOT EXISTS usage_counts (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (kind, key)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS usage_daily (
    day INTEGER PRIMARY KEY,
    queries INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_recent (
    id INTEGER PRIMARY KEY,
    entry TEXT NOT NULL
);

-- Materialised browse order, so any page is a primary-key range read rather than
-- an OFFSET scan. pos is dense from 1. The SBOM families ('' = every release with
-- an SBOM, then one per format family) are sorted by name and rebuilt by the
-- worker. '*products' and '*releases' cover the whole catalog, so save_release
-- appends to them in discovery order instead of anything rewriting them.
CREATE TABLE IF NOT EXISTS listing (
    family TEXT NOT NULL,
    pos INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    formats TEXT NOT NULL,
    PRIMARY KEY (family, pos)
) WITHOUT ROWID;

-- Running totals for /stats, adjusted by save_release in the same transaction so
-- the dashboard reads a few rows instead of scanning releases, wheels and sboms.
CREATE TABLE IF NOT EXISTS counters (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (kind, key)
) WITHOUT ROWID;

-- The same, bucketed by the UTC day a release was first seen, for /stats/timeseries.
CREATE TABLE IF NOT EXISTS daily_counters (
    day INTEGER NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (day, kind, key)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"""

_local = threading.local()

# Held for every write transaction this process makes, so its own writers queue
# here instead of in SQLite's busy handler. That handler polls with growing sleeps
# and favours whichever connection retries at the right moment: with the worker's
# job loops all writing at once, an unlucky one can lose every race for the whole
# busy_timeout and fail with "database is locked" though no transaction held the
# lock nearly that long. busy_timeout still covers waiting on other processes.
write_lock = threading.Lock()


def _configure(conn: sqlite3.Connection, *, readonly: bool) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA temp_store=MEMORY")
    # Small private page cache: every thread-pool thread holds its own connection,
    # so this is multiplied by threads x processes. The shared mmap and the OS page
    # cache do the real caching.
    conn.execute("PRAGMA cache_size=-4000")
    conn.execute("PRAGMA mmap_size=268435456")
    conn.execute("PRAGMA foreign_keys=OFF")
    if readonly:
        conn.execute("PRAGMA query_only=1")


def connect(path: str, *, readonly: bool = False) -> sqlite3.Connection:
    """Open a connection in autocommit mode; callers group writes with `with conn:` blocks."""
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    _configure(conn, readonly=readonly)
    return conn


def init_schema(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(_SCHEMA)
        _migrate(conn)
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring an older store up to SCHEMA_VERSION. The API and the worker may both start at once,
    so the version is re-read under the write lock and only one of them does the work."""
    from pypi_tea import store  # store imports this module

    if int(conn.execute("PRAGMA user_version").fetchone()[0]) >= SCHEMA_VERSION:
        return
    # Backfilling a large store holds the write lock for a while; a process starting
    # alongside should wait for it rather than fail its startup.
    conn.execute("PRAGMA busy_timeout=900000")
    begin(conn)
    try:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < 2:
            # 2: /stats reads counters, the catalog listings are appended to instead of rebuilt.
            conn.execute("DROP INDEX IF EXISTS sboms_release")  # a prefix of sboms_release_format
            store.recount(conn)
            store.rebuild_catalog_listing(conn)
        # 3: osv_scans and the sboms_sha256 index, both created by _SCHEMA; nothing to backfill.
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def reader(path: str) -> sqlite3.Connection:
    """Per-thread read-only connection. FastAPI runs sync routes on a thread pool."""
    conns: dict[str, sqlite3.Connection] | None = getattr(_local, "conns", None)
    if conns is None:
        conns = {}
        _local.conns = conns
    conn = conns.get(path)
    if conn is None:
        conn = connect(path, readonly=True)
        conns[path] = conn
    return conn


def writer(path: str) -> sqlite3.Connection:
    """Per-thread read-write connection."""
    conns: dict[str, sqlite3.Connection] | None = getattr(_local, "wconns", None)
    if conns is None:
        conns = {}
        _local.wconns = conns
    conn = conns.get(path)
    if conn is None:
        conn = connect(path)
        conns[path] = conn
    return conn


def is_busy(e: BaseException) -> bool:
    """Whether `e` is SQLite giving up on a lock another connection holds, rather than a real error."""
    return isinstance(e, sqlite3.OperationalError) and (getattr(e, "sqlite_errorcode", 0) & 0xFF) in (
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    )


def begin(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN IMMEDIATE")

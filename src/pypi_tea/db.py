"""SQLite storage: schema, connections, and pragmas.

One database file holds everything. Wheels are immutable once published, so a
resolved release is stored permanently and never re-fetched to serve a read.
WAL mode lets every API process read concurrently while the worker writes.
"""

import sqlite3
import threading
from pathlib import Path

SCHEMA_VERSION = 1

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
CREATE INDEX IF NOT EXISTS sboms_release ON sboms (name, version);
CREATE INDEX IF NOT EXISTS sboms_family ON sboms (family, name, version);

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
CREATE INDEX IF NOT EXISTS jobs_ready ON jobs (priority, not_before, claimed_until, enqueued_at);

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

-- Materialised browse order for /packages and the sitemap, rebuilt by the worker.
-- family = '' is the unfiltered listing. pos is dense from 1, so any page is a
-- primary-key range read rather than an OFFSET scan.
CREATE TABLE IF NOT EXISTS listing (
    family TEXT NOT NULL,
    pos INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    formats TEXT NOT NULL,
    PRIMARY KEY (family, pos)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"""

_local = threading.local()


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
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    finally:
        conn.close()


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


def begin(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN IMMEDIATE")

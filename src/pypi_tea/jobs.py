"""Work queue backed by the `jobs` table.

Jobs are keyed by (name, version) so enqueueing is idempotent: a release that
is already queued only has its priority raised. Claims are leases — a worker
that dies mid-job leaves `claimed_until` to lapse and another worker picks the
job up again.
"""

import sqlite3
import time
from dataclasses import dataclass

from pypi_tea.db import begin

PRIORITY_INTERACTIVE = 0
PRIORITY_BACKFILL = 5
PRIORITY_REFRESH = 9

LEASE_SECONDS = 300
MAX_ATTEMPTS = 5


@dataclass(frozen=True)
class Job:
    id: int
    name: str
    version: str
    priority: int
    attempts: int


def enqueue(conn: sqlite3.Connection, name: str, version: str, priority: int) -> None:
    conn.execute(
        """
        INSERT INTO jobs (name, version, priority, enqueued_at) VALUES (?, ?, ?, ?)
        ON CONFLICT (name, version) DO UPDATE SET priority = min(priority, excluded.priority)
        """,
        (name, version, priority, int(time.time())),
    )


def enqueue_many(conn: sqlite3.Connection, items: list[tuple[str, str]], priority: int) -> None:
    now = int(time.time())
    begin(conn)
    try:
        conn.executemany(
            """
            INSERT INTO jobs (name, version, priority, enqueued_at) VALUES (?, ?, ?, ?)
            ON CONFLICT (name, version) DO UPDATE SET priority = min(priority, excluded.priority)
            """,
            [(n, v, priority, now) for n, v in items],
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def claim(conn: sqlite3.Connection) -> Job | None:
    now = int(time.time())
    row = conn.execute(
        """
        UPDATE jobs SET claimed_until = ?, attempts = attempts + 1
        WHERE id = (
            SELECT id FROM jobs
            WHERE not_before <= ? AND claimed_until <= ?
            ORDER BY priority, enqueued_at
            LIMIT 1
        )
        RETURNING id, name, version, priority, attempts
        """,
        (now + LEASE_SECONDS, now, now),
    ).fetchone()
    if row is None:
        return None
    return Job(
        id=row["id"], name=row["name"], version=row["version"], priority=row["priority"], attempts=row["attempts"]
    )


def complete(conn: sqlite3.Connection, job: Job) -> None:
    conn.execute("DELETE FROM jobs WHERE id = ?", (job.id,))


def retry_later(conn: sqlite3.Connection, job: Job, error: str) -> bool:
    """Back off and release the claim. Returns False (and drops the job) once attempts are exhausted."""
    if job.attempts >= MAX_ATTEMPTS:
        conn.execute("DELETE FROM jobs WHERE id = ?", (job.id,))
        return False
    delay = min(3600, 30 * 2 ** (job.attempts - 1))
    conn.execute(
        "UPDATE jobs SET claimed_until = 0, not_before = ?, last_error = ? WHERE id = ?",
        (int(time.time()) + delay, error[:500], job.id),
    )
    return True


def pending_interactive(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT count(*) FROM jobs WHERE priority = ?", (PRIORITY_INTERACTIVE,)).fetchone()
    return int(row[0])


def is_queued(conn: sqlite3.Connection, name: str, version: str) -> bool:
    row = conn.execute("SELECT 1 FROM jobs WHERE name = ? AND version = ?", (name, version)).fetchone()
    return row is not None


def depth(conn: sqlite3.Connection) -> dict[int, int]:
    return {
        int(r["priority"]): int(r["n"])
        for r in conn.execute("SELECT priority, count(*) AS n FROM jobs GROUP BY priority")
    }

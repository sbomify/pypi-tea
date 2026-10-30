"""Usage counters, buffered in memory and flushed in one transaction every few seconds.

Counting every request with its own write would put the API processes in
contention with the worker for SQLite's single writer lock.
"""

import json
import threading
import time
from collections import Counter
from typing import Any

from pypi_tea import db
from pypi_tea.config import settings

FLUSH_SECONDS = 10.0
RECENT_MAX = 100
DAY = 86400


class UsageBuffer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[tuple[str, str]] = Counter()
        self._daily: Counter[int] = Counter()
        self._recent: list[dict[str, Any]] = []

    def endpoint(self, name: str) -> None:
        with self._lock:
            self._counts[("endpoint", name)] += 1

    def query(self, name: str, version: str, os_name: str | None, arch: str | None, has_sbom: bool) -> None:
        now = int(time.time())
        with self._lock:
            self._counts[("package", f"{name}@{version}")] += 1
            if os_name:
                self._counts[("os", os_name)] += 1
            if arch:
                self._counts[("arch", arch)] += 1
            if os_name or arch:
                self._counts[("qualified_queries", "")] += 1
            self._daily[now // DAY * DAY] += 1
            self._recent.append(
                {"package": name, "version": version, "os": os_name, "arch": arch, "has_sbom": has_sbom, "ts": now}
            )
            del self._recent[:-RECENT_MAX]

    def flush(self) -> None:
        with self._lock:
            counts, self._counts = self._counts, Counter()
            daily, self._daily = self._daily, Counter()
            recent, self._recent = self._recent, []
        if not (counts or daily or recent):
            return
        conn = db.writer(settings.database_path)
        try:
            db.begin(conn)
            conn.executemany(
                """
                INSERT INTO usage_counts (kind, key, count) VALUES (?, ?, ?)
                ON CONFLICT (kind, key) DO UPDATE SET count = count + excluded.count
                """,
                [(k, key, n) for (k, key), n in counts.items()],
            )
            conn.executemany(
                """
                INSERT INTO usage_daily (day, queries) VALUES (?, ?)
                ON CONFLICT (day) DO UPDATE SET queries = queries + excluded.queries
                """,
                list(daily.items()),
            )
            conn.executemany("INSERT INTO usage_recent (entry) VALUES (?)", [(json.dumps(e),) for e in recent])
            conn.execute(
                "DELETE FROM usage_recent WHERE id <= (SELECT coalesce(max(id), 0) FROM usage_recent) - ?",
                (RECENT_MAX,),
            )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            # Put the counts back so the next flush retries them instead of losing them.
            with self._lock:
                self._counts.update(counts)
                self._daily.update(daily)
                self._recent[:0] = recent
                del self._recent[:-RECENT_MAX]
            raise


usage = UsageBuffer()

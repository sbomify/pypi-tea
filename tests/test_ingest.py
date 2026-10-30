"""Wheel reading, the ingest pipeline, and the job queue."""

import asyncio
import json
import sqlite3
import time

import httpx
import pytest

from conftest import CDX, FakePyPI, make_wheel, sbom_wheel
from pypi_tea import db, jobs, store
from pypi_tea.ingest import ingest_release
from pypi_tea.services.wheel_reader import WheelError, read_members
from pypi_tea.worker import run_job

SBOM_DIR = ".dist-info/sboms/"


# --- wheel_reader ---


def test_range_reads_fetch_only_what_is_needed(fake_pypi: FakePyPI) -> None:
    wheel = sbom_wheel("demo", "1.0", filler=4 * 1024 * 1024)
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", wheel)])

    async def run() -> dict[str, bytes]:
        async with fake_pypi.client() as client:
            return await read_members(
                client, "https://files.example.com/demo-1.0-py3-none-any.whl", len(wheel), lambda n: SBOM_DIR in n
            )

    members = asyncio.run(run())
    assert list(members) == ["demo-1.0.dist-info/sboms/demo.cdx.json"]
    assert json.loads(members["demo-1.0.dist-info/sboms/demo.cdx.json"]) == CDX
    assert fake_pypi.bytes_served < 200 * 1024, "should read the central directory and one member, not the wheel"


def test_falls_back_to_full_download_without_range_support(fake_pypi: FakePyPI) -> None:
    fake_pypi.ranges = False
    wheel = sbom_wheel("demo", "1.0")
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", wheel)])

    async def run() -> dict[str, bytes]:
        async with fake_pypi.client() as client:
            return await read_members(
                client, "https://files.example.com/demo-1.0-py3-none-any.whl", len(wheel), lambda n: SBOM_DIR in n
            )

    assert len(asyncio.run(run())) == 1


def test_large_central_directory_is_fetched_in_rounds(fake_pypi: FakePyPI) -> None:
    members = {f"pkg/m{i:05d}_{'x' * 40}.py": b"" for i in range(3000)}
    members["demo-1.0.dist-info/sboms/demo.cdx.json"] = json.dumps(CDX).encode()
    wheel = make_wheel(members)
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", wheel)])

    async def run() -> dict[str, bytes]:
        async with fake_pypi.client() as client:
            return await read_members(
                client, "https://files.example.com/demo-1.0-py3-none-any.whl", len(wheel), lambda n: SBOM_DIR in n
            )

    assert list(asyncio.run(run())) == ["demo-1.0.dist-info/sboms/demo.cdx.json"]


def test_corrupt_wheel_is_a_permanent_error(fake_pypi: FakePyPI) -> None:
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", b"not a zip file at all" * 10)])

    async def run() -> None:
        async with fake_pypi.client() as client:
            await read_members(client, "https://files.example.com/demo-1.0-py3-none-any.whl", 210, lambda n: True)

    with pytest.raises(WheelError):
        asyncio.run(run())


# --- ingest ---


def _ingest(fake_pypi: FakePyPI, name: str, version: str) -> None:
    async def run() -> None:
        async with fake_pypi.client() as client:
            await ingest_release(client, name, version)

    asyncio.run(run())


def test_ingest_stores_release_wheels_and_sboms(database: str, fake_pypi: FakePyPI) -> None:
    fake_pypi.add(
        "demo",
        "1.0",
        [
            ("demo-1.0-py3-none-any.whl", sbom_wheel("demo", "1.0")),
            ("demo-1.0-cp312-cp312-win_amd64.whl", make_wheel({"demo/__init__.py": b""})),
        ],
    )
    _ingest(fake_pypi, "demo", "1.0")

    conn = db.connect(database)
    release = store.get_release(conn, "demo", "1.0")
    assert release is not None
    assert release.has_sbom
    assert release.info["summary"] == "demo"
    by_name = {w.filename: w for w in release.wheels}
    assert len(by_name["demo-1.0-py3-none-any.whl"].sboms) == 1
    assert by_name["demo-1.0-cp312-cp312-win_amd64.whl"].sboms == []
    sbom = by_name["demo-1.0-py3-none-any.whl"].sboms[0]
    assert sbom.format == "CycloneDX/1.6"
    content = store.get_sbom_content(conn, sbom.uuid)
    assert content is not None and json.loads(content[0]) == CDX
    assert by_name["demo-1.0-py3-none-any.whl"].attestation == {"status": "not_available"}


def test_reingest_does_not_refetch_immutable_wheels(database: str, fake_pypi: FakePyPI) -> None:
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", sbom_wheel("demo", "1.0"))])
    _ingest(fake_pypi, "demo", "1.0")
    before = len(fake_pypi.requests)
    _ingest(fake_pypi, "demo", "1.0")
    paths = [r.url.path for r in fake_pypi.requests[before:]]
    assert paths == ["/pypi/demo/1.0/json"]
    release = store.get_release(db.connect(database), "demo", "1.0")
    assert release is not None and release.has_sbom


def test_ingest_unknown_release_marks_missing(database: str, fake_pypi: FakePyPI) -> None:
    _ingest(fake_pypi, "nope", "9.9")
    conn = db.connect(database)
    assert store.get_release(conn, "nope", "9.9") is None
    assert store.is_missing(conn, "nope", "9.9")


def test_transient_wheel_error_fails_the_job(database: str, fake_pypi: FakePyPI) -> None:
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", sbom_wheel("demo", "1.0"))])

    def flaky(request: httpx.Request) -> httpx.Response:
        if request.url.host == "files.example.com":
            return httpx.Response(503)
        return fake_pypi.handler(request)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(flaky)) as client:
            await ingest_release(client, "demo", "1.0")

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(run())
    assert store.get_release(db.connect(database), "demo", "1.0") is None


def test_check_latest_job_queues_new_version(database: str, fake_pypi: FakePyPI) -> None:
    fake_pypi.add("demo", "2.0", [("demo-2.0-py3-none-any.whl", sbom_wheel("demo", "2.0"))])
    conn = db.connect(database)

    async def run() -> None:
        async with fake_pypi.client() as client:
            await run_job(client, jobs.Job(id=0, name="demo", version="", priority=9, attempts=1))

    asyncio.run(run())
    assert jobs.is_queued(conn, "demo", "2.0")


# --- jobs ---


def test_enqueue_is_idempotent_and_raises_priority(database: str) -> None:
    conn = db.connect(database)
    jobs.enqueue(conn, "a", "1", jobs.PRIORITY_REFRESH)
    jobs.enqueue(conn, "a", "1", jobs.PRIORITY_INTERACTIVE)
    jobs.enqueue(conn, "a", "1", jobs.PRIORITY_REFRESH)
    assert jobs.depth(conn) == {jobs.PRIORITY_INTERACTIVE: 1}


def test_claim_takes_highest_priority_and_leases(database: str) -> None:
    conn = db.connect(database)
    jobs.enqueue(conn, "low", "1", jobs.PRIORITY_REFRESH)
    jobs.enqueue(conn, "high", "1", jobs.PRIORITY_INTERACTIVE)
    first = jobs.claim(conn)
    second = jobs.claim(conn)
    assert first is not None and first.name == "high"
    assert second is not None and second.name == "low"
    assert jobs.claim(conn) is None, "leased jobs are not handed out twice"


def test_expired_lease_is_reclaimed(database: str) -> None:
    conn = db.connect(database)
    jobs.enqueue(conn, "a", "1", jobs.PRIORITY_REFRESH)
    job = jobs.claim(conn)
    assert job is not None
    conn.execute("UPDATE jobs SET claimed_until = ?", (int(time.time()) - 1,))
    again = jobs.claim(conn)
    assert again is not None and again.attempts == 2


def test_retry_backs_off_then_gives_up(database: str) -> None:
    conn = db.connect(database)
    jobs.enqueue(conn, "a", "1", jobs.PRIORITY_REFRESH)
    job = jobs.claim(conn)
    assert job is not None
    assert jobs.retry_later(conn, job, "boom")
    assert jobs.claim(conn) is None, "backed-off job waits for not_before"
    exhausted = jobs.Job(id=job.id, name="a", version="1", priority=9, attempts=jobs.MAX_ATTEMPTS)
    assert not jobs.retry_later(conn, exhausted, "boom")
    assert jobs.depth(conn) == {}


# --- review regressions ---


def _corrupt_member_wheel() -> bytes:
    """A wheel whose SBOM member's deflate stream is garbage (central directory intact)."""
    good = make_wheel({"demo-1.0.dist-info/sboms/demo.cdx.json": json.dumps(CDX).encode() * 50})
    marker = b"demo-1.0.dist-info/sboms/demo.cdx.json"
    start = good.index(marker) + len(marker)  # first occurrence: local header, data follows
    return good[:start] + bytes(b ^ 0xFF for b in good[start : start + 64]) + good[start + 64 :]


def test_corrupt_member_is_recorded_not_a_job_failure(database: str, fake_pypi: FakePyPI) -> None:
    fake_pypi.add(
        "demo",
        "1.0",
        [
            ("demo-1.0-py3-none-any.whl", _corrupt_member_wheel()),
            ("demo-1.0-cp312-cp312-win_amd64.whl", sbom_wheel("demo", "1.0")),
        ],
    )
    _ingest(fake_pypi, "demo", "1.0")
    release = store.get_release(db.connect(database), "demo", "1.0")
    assert release is not None
    by_name = {w.filename: w for w in release.wheels}
    assert by_name["demo-1.0-py3-none-any.whl"].error
    assert by_name["demo-1.0-cp312-cp312-win_amd64.whl"].has_sbom


def test_final_attempt_stores_release_and_retries_wheel_later(database: str, fake_pypi: FakePyPI) -> None:
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", sbom_wheel("demo", "1.0"))])
    down = {"files": True}

    def flaky(request: httpx.Request) -> httpx.Response:
        if request.url.host == "files.example.com" and down["files"]:
            return httpx.Response(503)
        return fake_pypi.handler(request)

    async def run(final: bool) -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(flaky)) as client:
            await ingest_release(client, "demo", "1.0", final_attempt=final)

    asyncio.run(run(True))
    release = store.get_release(db.connect(database), "demo", "1.0")
    assert release is not None and not release.has_sbom
    assert (release.wheels[0].error or "").startswith("retryable: ")

    down["files"] = False
    asyncio.run(run(False))
    release = store.get_release(db.connect(database), "demo", "1.0")
    assert release is not None and release.has_sbom, "a retryable error is re-inspected on the next resolve"
    assert release.wheels[0].error is None


def test_wheel_4xx_is_a_retryable_wheel_error(fake_pypi: FakePyPI) -> None:
    async def run() -> None:
        async with fake_pypi.client() as client:
            await read_members(client, "https://files.example.com/gone.whl", 1000, lambda n: True)

    with pytest.raises(WheelError) as exc:
        asyncio.run(run())
    assert exc.value.retryable


def test_name_spellings_share_one_release(database: str, fake_pypi: FakePyPI) -> None:
    from pypi_tea.tea import parse_purl

    assert parse_purl("pkg:pypi/Ruamel.YAML@0.18")[0] == "ruamel-yaml"
    assert parse_purl("pkg:pypi/ruamel_yaml@0.18")[0] == "ruamel-yaml"


def test_claim_uses_index_order(database: str) -> None:
    conn = db.connect(database)
    plan = " ".join(
        str(tuple(r))
        for r in conn.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM jobs WHERE not_before <= 0 AND claimed_until <= 0 "
            "ORDER BY priority, enqueued_at LIMIT 1"
        )
    )
    assert "jobs_order" in plan
    assert "TEMP B-TREE" not in plan


def test_raising_priority_clears_backoff(database: str) -> None:
    conn = db.connect(database)
    jobs.enqueue(conn, "a", "1", jobs.PRIORITY_REFRESH)
    job = jobs.claim(conn)
    assert job is not None
    jobs.retry_later(conn, job, "pypi down")
    assert jobs.claim(conn) is None
    jobs.enqueue(conn, "a", "1", jobs.PRIORITY_INTERACTIVE)
    again = jobs.claim(conn)
    assert again is not None and again.priority == jobs.PRIORITY_INTERACTIVE


def test_unchanged_reresolve_does_not_bump_catalog(database: str, fake_pypi: FakePyPI) -> None:
    fake_pypi.add("demo", "1.0", [("demo-1.0-py3-none-any.whl", sbom_wheel("demo", "1.0"))])
    conn = db.connect(database)
    _ingest(fake_pypi, "demo", "1.0")
    first = store.catalog_version(conn)
    _ingest(fake_pypi, "demo", "1.0")
    assert store.catalog_version(conn) == first
    fake_pypi.add("demo", "2.0", [("demo-2.0-py3-none-any.whl", sbom_wheel("demo", "2.0"))])
    _ingest(fake_pypi, "demo", "2.0")
    assert store.catalog_version(conn) == first + 1


def test_usage_flush_failure_keeps_counts(database: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from pypi_tea import usage as usage_mod

    buf = usage_mod.UsageBuffer()
    buf.query("demo", "1.0", None, None, True)

    def locked(_conn: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(usage_mod.db, "begin", locked)
    with pytest.raises(sqlite3.OperationalError):
        buf.flush()
    monkeypatch.undo()
    buf.flush()
    stats = store.usage_stats(db.connect(database))
    assert stats["top_packages"] == [{"package": "demo@1.0", "queries": 1}]

"""Vulnerability scanning: osv-scanner report parsing, the pypi-tea-osv run, and what package pages show."""

import json
import sqlite3
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from conftest import CDX, FakePyPI, sbom_wheel
from pypi_tea import db, scan, store
from pypi_tea.app import app
from pypi_tea.config import settings
from pypi_tea.ingest import ingest_release
from pypi_tea.models import ReleaseRecord, SbomRecord, WheelRecord
from pypi_tea.routes import pages
from pypi_tea.services import osv

pytestmark = pytest.mark.anyio

# One package from a real osv-scanner 2.7 report, trimmed: two OSV records for the same issue, grouped.
REQUESTS_ENTRY: dict[str, Any] = {
    "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI", "purl": "pkg:pypi/requests@2.19.0"},
    "groups": [
        {
            "ids": ["PYSEC-2018-28", "GHSA-x84v-xcm2-53pg"],
            "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"],
            "max_severity": "7.5",
        }
    ],
    "vulnerabilities": [
        {
            "id": "PYSEC-2018-28",
            "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [
                        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "c45d7c49ea75133e52ab"}]},
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]},
                    ],
                }
            ],
        },
        {
            "id": "GHSA-x84v-xcm2-53pg",
            "aliases": ["CVE-2018-18074", "PYSEC-2018-28"],
            "summary": "Insufficiently Protected Credentials in Requests",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
                }
            ],
        },
    ],
}

VULNERABLE_SBOM = {**CDX, "components": [{"type": "library", "name": "requests", "purl": "pkg:pypi/requests@2.19.0"}]}
CLEAN_SBOM = {**CDX, "components": [{"type": "library", "name": "requests", "purl": "pkg:pypi/requests@2.32.5"}]}

# Stands in for osv-scanner: same flags, exit codes and error messages, with REQUESTS_ENTRY as its whole database.
_FAKE_SCANNER = """\
import json, os, pathlib, sys

args = sys.argv[1:]
if args == ["--version"]:
    print("osv-scanner version: 9.9.9")
    sys.exit(0)
log = os.environ.get("FAKE_OSV_LOG")
if log:
    with open(log, "a") as f:
        f.write(json.dumps(args) + "\\n")
if os.environ.get("FAKE_OSV_DOWN"):
    print("Error during extraction: (extracting as vulnmatch/osvdev) max retries exceeded", file=sys.stderr)
    sys.exit(127)
paths = [args[i + 1] for i, a in enumerate(args) if a == "--lockfile"]
out = args[args.index("--output-file") + 1]
results, packages = [], 0
for p in paths:
    try:
        doc = json.loads(pathlib.Path(p).read_text())
    except ValueError:
        print(f"Error during extraction: (extracting as sbom/cdx) {p}: unexpected end of JSON input", file=sys.stderr)
        sys.exit(127)
    purls = [c.get("purl") for c in doc.get("components", []) if c.get("purl")]
    packages += len(purls)
    hits = [ENTRY for purl in purls if purl == ENTRY["package"]["purl"]]
    if hits:
        results.append({"source": {"path": str(pathlib.Path(p).resolve()), "type": "sbom"}, "packages": hits})
if not packages:
    print("No package sources found", file=sys.stderr)
    sys.exit(128)
pathlib.Path(out).write_text(json.dumps({"results": results}))
sys.exit(1 if results else 0)
"""


@pytest.fixture()
def fake_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "osv-scanner"
    body = _FAKE_SCANNER.replace("ENTRY", "_ENTRY")
    path.write_text(f"#!{sys.executable}\n_ENTRY = {REQUESTS_ENTRY!r}\n{body}")
    path.chmod(0o755)
    log = tmp_path / "osv-calls.log"
    monkeypatch.setattr(settings, "osv_scanner_path", str(path))
    monkeypatch.setenv("FAKE_OSV_LOG", str(log))
    return log


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
async def client(database: str) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _seed(fake_pypi: FakePyPI, name: str, version: str, *sboms: dict[str, Any]) -> None:
    wheels = [(f"{name}-{version}-py3-none-{i}.whl", sbom_wheel(name, version, s)) for i, s in enumerate(sboms)]
    fake_pypi.add(name, version, wheels)
    async with fake_pypi.client() as c:
        await ingest_release(c, name, version)


def _calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def _save_raw(conn: sqlite3.Connection, name: str, contents: list[str]) -> None:
    wheels = []
    for i, content in enumerate(contents):
        url = f"https://files.example.com/{name}-{i}.whl"
        sha = f"{i:064d}"
        sbom = SbomRecord(f"{name}-{i}", "x.cdx.json", "application/vnd.cyclonedx+json", sha, "CycloneDX/1.6", True)
        sbom.content = content
        wheels.append(WheelRecord(url=url, filename=f"{name}-{i}.whl", digests={}, size=1, sboms=[sbom]))
    store.save_release(conn, ReleaseRecord(name=name, version="1", created=None, info={}, wheels=wheels))


def test_findings_from_a_grouped_report() -> None:
    (finding,) = osv.findings_from_package(REQUESTS_ENTRY)
    assert finding["id"] == "CVE-2018-18074"
    assert finding["aliases"] == ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]
    assert finding["summary"] == "Insufficiently Protected Credentials in Requests"
    assert (finding["severity"], finding["score"]) == ("high", 7.5)
    # Git commit "fixes" aren't versions anyone can upgrade to.
    assert finding["fixed"] == ["2.20.0"]
    assert (finding["package"], finding["version"], finding["ecosystem"]) == ("requests", "2.19.0", "PyPI")


def test_fixed_in_is_the_fix_for_the_installed_release_line() -> None:
    events = [{"introduced": "0"}, {"fixed": "0.2.0"}, {"introduced": "0.2.1"}, {"fixed": "0.2.23"}]
    package = {"name": "time", "version": "0.1.45", "ecosystem": "crates.io"}
    entry: dict[str, Any] = {
        "package": package,
        "groups": [{"ids": ["RUSTSEC-2020-0071"], "aliases": ["CVE-2020-26235"], "max_severity": "6.2"}],
        "vulnerabilities": [
            {
                "id": "RUSTSEC-2020-0071",
                "affected": [
                    {
                        "package": {"name": "time", "ecosystem": "crates.io"},
                        "ranges": [{"type": "SEMVER", "events": events}],
                    }
                ],
            }
        ],
    }
    assert osv.findings_from_package(entry)[0]["fixed"] == ["0.2.0"]
    package["version"] = "0.2.5"
    assert osv.findings_from_package(entry)[0]["fixed"] == ["0.2.23"]
    # A version PEP 440 can't order: every fix OSV lists.
    package["version"] = "1:0.2.5~git"
    assert osv.findings_from_package(entry)[0]["fixed"] == ["0.2.0", "0.2.23"]


def test_advisories_link_to_insights_and_the_rest_to_osv() -> None:
    insights = "https://insights.sbomify.com"
    assert pages.vulnerability_url("CVE-2018-18074") == f"{insights}/CVE-2018-18074/"
    assert pages.vulnerability_url("RUSTSEC-2024-0384") == f"{insights}/RUSTSEC-2024-0384/"
    assert pages.vulnerability_url("GHSA-x84v-xcm2-53pg") == f"{insights}/GHSA-x84v-xcm2-53pg/"
    assert pages.vulnerability_url("PYSEC-2024-1") == f"{insights}/PYSEC-2024-1/"
    assert pages.vulnerability_url("GO-2021-0113") == f"{insights}/GO-2021-0113/"
    assert pages.vulnerability_url("MAL-2024-9506") == f"{insights}/MAL-2024-9506/"
    assert pages.vulnerability_url("OSV-2021-1234") == f"{insights}/OSV-2021-1234/"
    assert pages.vulnerability_url("SUSE-SU-2015:0803-1") == f"{insights}/SUSE-SU-2015-0803-1/"
    assert pages.vulnerability_url("openSUSE-SU-2016:2484-1") == f"{insights}/openSUSE-SU-2016-2484-1/"
    # Schemes Insights has no page of their own for stay on OSV.
    assert pages.vulnerability_url("DSA-5020-1") == "https://osv.dev/vulnerability/DSA-5020-1"
    assert pages.vulnerability_url("USN-5192-1") == "https://osv.dev/vulnerability/USN-5192-1"


def test_severity_labels_follow_cvss() -> None:
    assert [osv.severity_label(s) for s in (9.8, 7.0, 4.0, 0.1, 0.0, None)] == [
        "critical",
        "high",
        "medium",
        "low",
        "none",
        "unknown",
    ]


async def test_scan_stores_findings_and_pages_show_them(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, fake_scanner: Path
) -> None:
    await _seed(fake_pypi, "acme", "1.0", VULNERABLE_SBOM, CLEAN_SBOM)

    page = await client.get("/package/acme/1.0")
    assert "Known vulnerabilities" not in page.text  # not scanned yet: say nothing rather than "none"

    assert scan.run() == (2, 1, 0)
    assert len(_calls(fake_scanner)) == 1  # both SBOMs in one osv-scanner run

    page = await client.get("/package/acme/1.0")
    assert "1 known vulnerability" in page.text
    assert 'href="https://insights.sbomify.com/CVE-2018-18074/"' in page.text
    assert "Insufficiently Protected Credentials in Requests" in page.text
    assert "1 of 2 wheels" in page.text
    assert "no known vulnerabilities" in page.text  # the clean wheel's SBOM

    markdown = (await client.get("/package/acme/1.0.md")).text
    assert "## Known vulnerabilities" in markdown
    assert "| [CVE-2018-18074](https://insights.sbomify.com/CVE-2018-18074/) | high (7.5) |" in markdown
    assert "\n\n\n" not in markdown

    data = (await client.get("/package/acme/1.0.json")).json()
    (vuln,) = data["vulnerabilities"]
    assert vuln["id"] == "CVE-2018-18074" and vuln["fixed"] == ["2.20.0"]
    assert vuln["url"] == "https://insights.sbomify.com/CVE-2018-18074/"
    assert vuln["wheels"] == ["acme-1.0-py3-none-0.whl"]
    assert data["vulnerability_scan"]["scanned_sboms"] == 2
    assert data["vulnerability_scan"]["severity_counts"] == {"high": 1}
    counts = sorted(s["vulnerability_count"] for w in data["wheels"] for s in w["sboms"])
    assert counts == [0, 1]


async def test_clean_release_says_so(client: httpx.AsyncClient, fake_pypi: FakePyPI, fake_scanner: Path) -> None:
    await _seed(fake_pypi, "tidy", "2.0", CLEAN_SBOM)
    scan.run()
    page = await client.get("/package/tidy/2.0")
    assert "No known vulnerabilities" in page.text
    assert "OSV has no known vulnerabilities" in (await client.get("/package/tidy/2.0.md")).text


async def test_only_due_sboms_are_rescanned(database: str, fake_pypi: FakePyPI, fake_scanner: Path) -> None:
    await _seed(fake_pypi, "acme", "1.0", VULNERABLE_SBOM)
    # The same SBOM in a second release is the same document: scanned once.
    await _seed(fake_pypi, "acme", "1.1", VULNERABLE_SBOM)
    assert scan.run() == (1, 1, 0)
    assert scan.run() == (0, 0, 0)
    assert scan.run(rescan_all=True) == (1, 1, 0)
    assert len(_calls(fake_scanner)) == 2


async def test_unreadable_sbom_is_recorded_without_failing_the_batch(database: str, fake_scanner: Path) -> None:
    conn = db.connect(database)
    _save_raw(conn, "mixed", [json.dumps(VULNERABLE_SBOM), "{", json.dumps(CLEAN_SBOM)])
    assert scan.run() == (3, 1, 1)
    scans = store.osv_scans(conn, [f"{i:064d}" for i in range(3)])
    assert [len(scans[f"{i:064d}"]["findings"]) for i in range(3)] == [1, 0, 0]
    assert "unexpected end of JSON input" in scans[f"{1:064d}"]["error"]
    # The batch, then each SBOM on its own to find the broken one.
    assert len(_calls(fake_scanner)) == 4


async def test_scanner_outage_records_nothing(
    database: str, fake_scanner: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = db.connect(database)
    _save_raw(conn, "acme", [json.dumps(VULNERABLE_SBOM), json.dumps(CLEAN_SBOM)])
    monkeypatch.setenv("FAKE_OSV_DOWN", "1")
    with pytest.raises(osv.ScannerUnavailable):
        scan.run()
    assert conn.execute("SELECT count(*) FROM osv_scans").fetchone()[0] == 0


async def test_missing_scanner_is_unavailable(database: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(settings, "osv_scanner_path", str(tmp_path / "nope"))
    with pytest.raises(osv.ScannerUnavailable):
        scan.run()


async def test_scans_survive_a_reresolve_and_are_pruned_with_their_sbom(database: str, fake_scanner: Path) -> None:
    conn = db.connect(database)
    _save_raw(conn, "acme", [json.dumps(VULNERABLE_SBOM)])
    scan.run()
    sha = f"{0:064d}"
    _save_raw(conn, "acme", [json.dumps(VULNERABLE_SBOM)])  # re-resolve: same SBOM rows replaced
    assert sha in store.osv_scans(conn, [sha])
    store.save_release(conn, ReleaseRecord(name="acme", version="1", created=None, info={}, wheels=[]))
    assert store.prune_osv_scans(conn) == 1
    assert store.osv_scans(conn, [sha]) == {}


def test_schema_v2_store_migrates(tmp_path: Path) -> None:
    path = str(tmp_path / "old.db")
    db.init_schema(path)
    conn = db.connect(path)
    conn.execute("DROP TABLE osv_scans")
    conn.execute("DROP INDEX sboms_sha256")
    conn.execute("PRAGMA user_version=2")
    conn.close()
    db.init_schema(path)
    conn = db.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert conn.execute("SELECT count(*) FROM osv_scans").fetchone()[0] == 0

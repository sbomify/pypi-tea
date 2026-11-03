"""Run osv-scanner over stored SBOMs and reduce its report to what a package page shows.

osv-scanner reads CycloneDX and SPDX documents, matches every package URL in them
against the OSV database (api.osv.dev), and reports each match. A batch of SBOMs
is scanned in one run. One unreadable SBOM fails the whole run, so a failed batch
is retried one SBOM at a time to pin the failure on the document that caused it.
"""

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

# osv-scanner exit codes: 0 nothing found, 1 vulnerabilities found, 128 no packages found.
_OK_CODES = {0, 1, 128}
_NO_PACKAGES = 128

# osv-scanner only recognises an SBOM by its file name.
_SUFFIXES = {
    "application/vnd.cyclonedx+json": ".cdx.json",
    "application/vnd.cyclonedx+xml": ".cdx.xml",
    "application/spdx+json": ".spdx.json",
    "text/spdx": ".spdx",
    "application/spdx+rdf": ".spdx.rdf",
}


class ScannerUnavailable(Exception):
    """osv-scanner failed for a reason that isn't the SBOM: missing binary, no network, OSV API down."""


@dataclass
class SbomToScan:
    sha256: str
    media_type: str
    content: bytes


@dataclass
class ScanResult:
    findings: list[dict[str, Any]]
    # Set when osv-scanner could not read this SBOM; findings is then empty.
    error: str | None = None


def scannable(media_type: str) -> bool:
    return media_type in _SUFFIXES


def scanner_version(binary: str) -> str:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise ScannerUnavailable(f"{binary} --version failed: {e}") from e
    for line in out.splitlines():
        if line.startswith("osv-scanner version:"):
            return line.split(":", 1)[1].strip()
    return out.strip().splitlines()[0] if out.strip() else "unknown"


def severity_label(score: float | None) -> str:
    """CVSS base score to the qualitative rating CVSS itself defines."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _score(value: object) -> float | None:
    try:
        return float(str(value))
    except ValueError:
        return None


def _parse(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _fix_for(events: list[dict[str, str]], installed: Version) -> str | None:
    """The fix that closes the affected interval `installed` falls in. None if it's in none."""
    introduced: Version | None = None
    for event in events:
        if "introduced" in event:
            introduced = _parse(event["introduced"])
        elif "fixed" in event and introduced is not None:
            fixed = _parse(event["fixed"])
            if fixed is not None and introduced <= installed < fixed:
                return event["fixed"]
    return None


def _fixed_versions(vuln: dict[str, Any], name: str, ecosystem: str, version: str) -> list[str]:
    """Versions that fix `vuln` for this package. Where the versions compare (PEP 440 parses most
    ecosystems' release numbers), only the fix for the range the installed version is in;
    otherwise every fix OSV lists, since some of them are for other release lines."""
    ranges = [
        r.get("events") or []
        for affected in vuln.get("affected") or []
        if (affected.get("package") or {}).get("name") == name
        and (affected.get("package") or {}).get("ecosystem") == ecosystem
        for r in affected.get("ranges") or []
        if r.get("type") != "GIT"
    ]
    installed = _parse(version)
    if installed is not None:
        for events in ranges:
            fix = _fix_for(events, installed)
            if fix is not None:
                return [fix]
    return list(dict.fromkeys(e["fixed"] for events in ranges for e in events if e.get("fixed")))


def _display_id(ids: list[str], aliases: list[str]) -> str:
    """The CVE when there is one, since that's what people search for; otherwise OSV's first id."""
    cves = sorted(a for a in [*ids, *aliases] if a.startswith("CVE-"))
    return cves[0] if cves else ids[0]


def findings_from_package(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """One finding per vulnerability group (OSV merges aliases of the same issue into a group)."""
    pkg = entry.get("package") or {}
    name, version, ecosystem = pkg.get("name", ""), pkg.get("version", ""), pkg.get("ecosystem", "")
    vulns = {v["id"]: v for v in entry.get("vulnerabilities") or [] if v.get("id")}
    groups = entry.get("groups") or [{"ids": [i], "aliases": vulns[i].get("aliases") or []} for i in vulns]
    findings = []
    for group in groups:
        ids = [i for i in group.get("ids") or [] if i]
        if not ids:
            continue
        aliases = sorted({*ids, *(group.get("aliases") or [])})
        members = [vulns[i] for i in ids if i in vulns]
        summary = next((v["summary"] for v in members if v.get("summary")), None)
        fixed: list[str] = []
        for v in members:
            fixed.extend(f for f in _fixed_versions(v, name, ecosystem, version) if f not in fixed)
        score = _score(group.get("max_severity"))
        shown = _display_id(ids, aliases)
        findings.append(
            {
                "id": shown,
                "aliases": [a for a in aliases if a != shown],
                "summary": summary,
                "severity": severity_label(score),
                "score": score,
                "package": name,
                "version": version,
                "ecosystem": ecosystem,
                "purl": pkg.get("purl"),
                "fixed": fixed,
            }
        )
    return findings


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unknown": 5}


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings, key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), -(f["score"] or 0), f["package"], f["id"])
    )


def _run(binary: str, paths: list[Path], out: Path, timeout: float) -> tuple[int, str]:
    cmd = [binary, "scan", "source", "--format", "json", "--output-file", str(out), "--verbosity", "error"]
    for p in paths:
        cmd += ["--lockfile", str(p)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=paths[0].parent)
    except FileNotFoundError as e:
        raise ScannerUnavailable(f"osv-scanner not found at {binary}") from e
    except subprocess.TimeoutExpired as e:
        raise ScannerUnavailable(f"osv-scanner timed out after {timeout:.0f}s") from e
    return proc.returncode, proc.stderr.strip()


def _is_sbom_error(stderr: str) -> bool:
    """Whether a failure was osv-scanner rejecting the document, rather than the lookup failing."""
    return "extracting as sbom/" in stderr


def scan(binary: str, sboms: list[SbomToScan], timeout: float) -> dict[str, ScanResult]:
    """Scan SBOMs and return a result per sha256. Raises ScannerUnavailable if nothing could be scanned."""
    if not sboms:
        return {}
    with tempfile.TemporaryDirectory(prefix="pypi-tea-osv-") as tmp:
        root = Path(tmp)
        paths: dict[str, Path] = {}
        for i, s in enumerate(sboms):
            path = root / f"{i}{_SUFFIXES[s.media_type]}"
            path.write_bytes(s.content)
            paths[s.sha256] = path
        return _scan_paths(binary, paths, root / "report.json", timeout)


def _scan_paths(binary: str, paths: dict[str, Path], out: Path, timeout: float) -> dict[str, ScanResult]:
    code, stderr = _run(binary, list(paths.values()), out, timeout)
    if code in _OK_CODES:
        results = {sha: ScanResult(findings=[]) for sha in paths}
        if code == _NO_PACKAGES:
            return results
        by_path = {str(p.resolve()): sha for sha, p in paths.items()}
        report = json.loads(out.read_text())
        for source in report.get("results") or []:
            sha = by_path.get(str(Path((source.get("source") or {}).get("path", "")).resolve()))
            if sha is None:
                continue
            for entry in source.get("packages") or []:
                results[sha].findings.extend(findings_from_package(entry))
        for r in results.values():
            r.findings = sort_findings(r.findings)
        return results
    if len(paths) > 1 and _is_sbom_error(stderr):
        logger.info("batch of %d failed on an unreadable SBOM; scanning them one at a time", len(paths))
        results = {}
        for sha, path in paths.items():
            results.update(_scan_paths(binary, {sha: path}, out, timeout))
        return results
    if len(paths) == 1 and _is_sbom_error(stderr):
        (sha,) = paths
        return {sha: ScanResult(findings=[], error=stderr.splitlines()[-1][:500] if stderr else f"exit {code}")}
    raise ScannerUnavailable(f"osv-scanner exited {code}: {stderr[-500:]}")

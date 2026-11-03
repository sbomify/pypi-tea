"""Vulnerability scan of every stored SBOM with osv-scanner.

Usage:
    pypi-tea-osv                 # scan SBOMs never scanned, or not scanned in PYPI_TEA_OSV_RESCAN_HOURS
    pypi-tea-osv --limit 100     # at most this many SBOMs this run
    pypi-tea-osv --all           # rescan every SBOM now

A separate process from the ingest worker, meant to run from a timer: it reads the
stored SBOMs, sends their package URLs to OSV through osv-scanner and writes one
row per SBOM to `osv_scans`, which the package pages read. Scans are keyed by the
SBOM's SHA-256, so the same document shipped in many wheels is scanned once.

Exit codes: 0 ok, 2 error (including osv-scanner or OSV being unavailable), 130 interrupted.
"""

import argparse
import logging
import sys
import time

from pypi_tea import db, sentry, store
from pypi_tea.config import settings
from pypi_tea.services import osv

logger = logging.getLogger("pypi_tea.scan")


def run(limit: int = 0, rescan_all: bool = False) -> tuple[int, int, int]:
    """Scan what's due. Returns (SBOMs scanned, SBOMs with findings, SBOMs osv-scanner couldn't read)."""
    db.init_schema(settings.database_path)
    conn = db.writer(settings.database_path)
    scanner = f"osv-scanner {osv.scanner_version(settings.osv_scanner_path)}"
    cutoff = int(time.time()) + 1 if rescan_all else int(time.time() - settings.osv_rescan_hours * 3600)
    due = store.sboms_due_for_scan(conn, cutoff, limit or -1)
    logger.info("%d SBOMs due for a scan with %s", len(due), scanner)
    scanned = vulnerable = unreadable = 0
    batch_size = max(1, settings.osv_batch_size)
    for start in range(0, len(due), batch_size):
        batch: list[osv.SbomToScan] = []
        results: list[tuple[str, str | None, list[dict[str, object]]]] = []
        for sha in due[start : start + batch_size]:
            stored = store.sbom_for_scan(conn, sha)
            if stored is None:
                continue  # replaced since the due list was read
            content, media_type = stored
            if osv.scannable(media_type):
                batch.append(osv.SbomToScan(sha, media_type, content))
            else:
                results.append((sha, f"osv-scanner does not read {media_type}", []))
        for sha, result in osv.scan(settings.osv_scanner_path, batch, settings.osv_timeout_seconds).items():
            results.append((sha, result.error, list(result.findings)))
        store.save_osv_scans(conn, scanner, results)
        scanned += len(results)
        vulnerable += sum(1 for _, _, findings in results if findings)
        unreadable += sum(1 for _, error, _ in results if error)
        logger.info("scanned %d/%d", min(start + batch_size, len(due)), len(due))
    pruned = store.prune_osv_scans(conn)
    if pruned:
        logger.info("dropped %d scans of SBOMs no longer stored", pruned)
    return scanned, vulnerable, unreadable


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan stored SBOMs for known vulnerabilities with osv-scanner")
    parser.add_argument("--limit", type=int, default=0, help="Scan at most this many SBOMs")
    parser.add_argument("--all", action="store_true", help="Rescan every SBOM, however recently scanned")
    args = parser.parse_args()
    scanned, vulnerable, unreadable = run(limit=args.limit, rescan_all=args.all)
    logger.info("done: %d SBOMs scanned, %d with known vulnerabilities, %d unreadable", scanned, vulnerable, unreadable)


def cli() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    sentry.init("osv")
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except osv.ScannerUnavailable as e:
        # Nothing about the SBOMs is recorded, so the next run picks up where this one stopped.
        logger.error("osv-scanner unavailable: %s", e)
        sys.exit(2)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(2)


if __name__ == "__main__":
    cli()

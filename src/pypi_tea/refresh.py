"""Queue maintenance CLI.

Usage:
    pypi-tea-refresh                          # check every known project for a new release
    pypi-tea-refresh --existing               # ...and re-resolve every known release
    pypi-tea-refresh --limit 100              # cap the number of projects
    pypi-tea-refresh --import-redis URL        # queue every release a 0.x (Redis) instance knew about
    pypi-tea-refresh --status                 # print queue depth per priority

Exit codes: 0 ok, 2 error, 130 interrupted.
"""

import argparse
import logging
import sys

from packaging.utils import canonicalize_name

from pypi_tea import db, jobs
from pypi_tea.config import settings
from pypi_tea.worker import enqueue_refresh

logger = logging.getLogger("pypi_tea.refresh")


def import_redis(redis_url: str) -> tuple[int, int]:
    """Queue releases from a 0.x Redis keyspace: ones with SBOMs first, so their pages come back soonest."""
    try:
        import redis
    except ImportError:
        raise SystemExit("--import-redis needs the redis client: install pypi-tea[import-redis]") from None

    r = redis.Redis.from_url(redis_url, decode_responses=True)

    def members(key: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for entry in r.sscan_iter(key, count=1000):
            name, sep, version = str(entry).rpartition("@")
            if sep and name and version:
                out.append((str(canonicalize_name(name)), version))
        return out

    conn = db.writer(settings.database_path)
    with_sbom = members("unique:packages_with_sbom")
    jobs.enqueue_many(conn, with_sbom, jobs.PRIORITY_BACKFILL)
    seen = set(with_sbom)
    rest = [k for k in members("unique:packages") if k not in seen]
    jobs.enqueue_many(conn, rest, jobs.PRIORITY_BACKFILL + 1)
    return len(with_sbom), len(rest)


def main() -> None:
    parser = argparse.ArgumentParser(description="Queue pypi-tea refresh work")
    parser.add_argument("--existing", action="store_true", help="Also re-resolve every known release")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of projects")
    parser.add_argument("--import-redis", metavar="REDIS_URL", help="Queue every release known to a 0.x Redis instance")
    parser.add_argument("--status", action="store_true", help="Print queue depth and exit")
    args = parser.parse_args()

    db.init_schema(settings.database_path)
    if args.status:
        for priority, n in sorted(jobs.depth(db.writer(settings.database_path)).items()):
            print(f"priority {priority}: {n}")
        return
    if args.import_redis:
        sboms, rest = import_redis(args.import_redis)
        logger.info("queued %d releases with SBOMs and %d without from %s", sboms, rest, args.import_redis)
        return
    projects, releases = enqueue_refresh(existing=args.existing, limit=args.limit)
    logger.info("queued %d project checks and %d release re-resolves", projects, releases)


def cli() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(2)


if __name__ == "__main__":
    cli()

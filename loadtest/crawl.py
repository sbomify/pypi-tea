"""Crawler-shaped load generator (Googlebot-style mix) with per-route latency stats."""

import argparse
import asyncio
import random
import statistics
import time
import uuid
from collections import Counter, defaultdict

import httpx

NS = uuid.UUID("d4f1a3b2-7e6c-4a8f-9b0d-2c5e8f1a3b7d")
ROOT = "http://127.0.0.1:9100"


def u(s: str) -> str:
    return str(uuid.uuid5(NS, s))


def make_request(with_sbom: int, total: int) -> tuple[str, str]:
    r = random.random()
    i = random.randrange(with_sbom)
    name = f"pkg{i}"
    if r < 0.45:
        return "package_page", f"/package/{name}/1.0.0"
    if r < 0.60:
        return "packages_list", f"/packages?page={random.randint(1, with_sbom // 50)}"
    if r < 0.68:
        return "packages_fmt", f"/packages?format=CycloneDX&page={random.randint(1, with_sbom // 50)}"
    if r < 0.88:
        fn = f"{name}-1.0.0-cp312-cp312-manylinux_2_17_x86_64_{random.randrange(3)}.whl"
        wurl = f"{ROOT}/files/{fn}"
        a = u(f"sbom:{wurl}:{name}-1.0.0.dist-info/sboms/{name}.cdx.json")
        return "artifact_download", f"/artifact/{a}/download"
    if r < 0.965:
        j = random.randrange(total)
        return "discovery", f"/discovery?tei=urn:tei:purl:localhost:pkg:pypi/pkg{j}@1.0.0"
    if r < 0.98:
        return "discovery_new", f"/discovery?tei=urn:tei:purl:localhost:pkg:pypi/new{random.randrange(10**9)}@1.0.0"
    return "sitemap", "/sitemap.xml"


async def worker(client, deadline, stats, args):
    while time.monotonic() < deadline:
        kind, path = make_request(args.with_sbom, args.total)
        t0 = time.monotonic()
        try:
            resp = await client.get(path)
            await resp.aread()
            code = str(resp.status_code)
        except httpx.TimeoutException:
            code = "timeout"
        except httpx.HTTPError as e:
            code = type(e).__name__
        stats[kind].append((time.monotonic() - t0, code))


async def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("base")
    p.add_argument("--concurrency", type=int, default=50)
    p.add_argument("--duration", type=float, default=30)
    p.add_argument("--with-sbom", type=int, default=20000)
    p.add_argument("--total", type=int, default=100000)
    p.add_argument("--timeout", type=float, default=30)
    args = p.parse_args()
    stats: dict[str, list[tuple[float, str]]] = defaultdict(list)
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    async with httpx.AsyncClient(base_url=args.base, timeout=args.timeout, limits=limits) as client:
        deadline = time.monotonic() + args.duration
        await asyncio.gather(*(worker(client, deadline, stats, args) for _ in range(args.concurrency)))
    total = sum(len(v) for v in stats.values())
    print(f"total={total} rps={total / args.duration:.1f}")
    print(f"{'route':<18} {'n':>6} {'p50ms':>8} {'p95ms':>8} {'p99ms':>8} {'maxms':>8}  codes")
    for kind in sorted(stats):
        lat = sorted(x[0] * 1000 for x in stats[kind])
        codes = Counter(x[1] for x in stats[kind])
        q = statistics.quantiles(lat, n=100) if len(lat) > 1 else [lat[0]] * 99
        print(f"{kind:<18} {len(lat):>6} {q[49]:>8.0f} {q[94]:>8.0f} {q[98]:>8.0f} {lat[-1]:>8.0f}  {dict(codes)}")


asyncio.run(main())

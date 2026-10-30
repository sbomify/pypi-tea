# Load testing

A crawler-shaped load test: package pages, `/packages` listings (all pages, with and
without a format filter), SBOM downloads, TEA discovery for known and never-seen
releases, and sitemap shards. Upstream PyPI is replaced by a mock with configurable
latency, so nothing here touches the real PyPI.

```bash
# 1. Mock PyPI (JSON API + range-capable wheels), 200 ms per response
MOCK_DELAY=0.2 uv run --with starlette --with uvicorn uvicorn mockpypi:app --port 9100

# 2. Seed 100k releases, 20k with SBOMs, and export artifact UUIDs for wrk
uv run --project .. python seed.py lt.db 100000 20000
sqlite3 lt.db "select uuid from sboms limit 20000" > uuids.txt

# 3. API and worker
export PYPI_TEA_DATABASE_PATH=lt.db PYPI_TEA_PYPI_BASE_URL=http://127.0.0.1:9100 PYPI_TEA_ATTESTATION_VERIFICATION=false
PYPI_TEA_BIND=127.0.0.1:8003 PYPI_TEA_WEB_WORKERS=4 uv run --project .. pypi-tea-serve &
uv run --project .. pypi-tea-worker &

# 4a. Per-route latency breakdown (Python client; tops out around 500 req/s per process)
uv run --project .. python crawl.py http://127.0.0.1:8003 --concurrency 50 --duration 30

# 4b. Saturation (wrk)
wrk -t4 -c256 -d20s --latency -s crawl.lua http://127.0.0.1:8003
```

Profile a running API worker with `sudo py-spy record --pid <worker pid> --gil -f raw -o out.txt`.

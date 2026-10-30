# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

pypi-tea is a [Transparency Exchange API (TEA)](https://github.com/CycloneDX/transparency-exchange-api) server that extracts and serves SBOMs from PyPI package wheel files. A worker inspects wheels with HTTP range requests and stores the results in SQLite; a FastAPI app serves TEA endpoints and SEO pages from that store.

## Commands

```bash
# Install dependencies (requires Python 3.14+ and uv)
uv sync --group dev

# Run API + worker in one process (development)
PYPI_TEA_EMBEDDED_WORKER=true uv run uvicorn pypi_tea.app:app

# Production entry points
uv run pypi-tea-serve      # gunicorn + uvicorn workers, SO_REUSEPORT
uv run pypi-tea-worker     # ingest worker

# Run tests (no services needed; conformance tests reach live PyPI)
uv run pytest tests/ -v

# Run a single test
uv run pytest tests/test_conformance.py::test_tea_conformance[check_name] -v

# Lint and format
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Type check (strict mode with pydantic plugin)
uv run mypy src/
```

## Architecture

The one rule: **the API process never does upstream I/O.** Request handlers only read SQLite. Anything that needs PyPI goes through the `jobs` table to the worker.

Request flow for a TEI/PURL: route handler → `lookup.ensure_release()` → stored release if present; otherwise enqueue an interactive job and poll for a bounded time, raising `Pending` / `Overloaded` (both become 503 + Retry-After). The worker claims the job → `ingest.ingest_release()` → PyPI JSON → `services/wheel_reader.py` range-reads `.dist-info/sboms/` → format detection/validation and attestation → `store.save_release()` in one transaction.

### Key layers

- **`app.py`** — FastAPI app, lifespan (schema init, usage flusher, optional embedded worker), pure-ASGI `EdgeMiddleware` (request deadline, cache headers, endpoint counters), `/healthz`
- **`serve.py`** — `pypi-tea-serve`: gunicorn with `reuse_port` and a uvicorn worker class that sets `limit_concurrency`
- **`config.py`** — pydantic-settings with `PYPI_TEA_` env prefix
- **`db.py`** — schema and connections. WAL mode; one read-only connection per thread (`db.reader`) and one read-write (`db.writer`)
- **`store.py`** — all SQL: reads for the API, `save_release` for the worker, stats aggregates, `rebuild_listing`
- **`jobs.py`** — queue on the `jobs` table: idempotent enqueue keyed by (name, version), leased claims, backoff
- **`lookup.py`** — read-path helpers: `read()` runs a store query off the event loop; `ensure_release()` does bounded on-demand resolution; `memoized()` is a bounded, single-flight, per-process TTL cache for aggregates
- **`ingest.py`** — resolve one release; reuses already-inspected wheels (immutable) and only re-checks non-final attestations
- **`worker.py`** — `pypi-tea-worker`: N job loops plus a scheduler (listing rebuild as soon as the catalog changes, at most a 10% duty cycle; weekly refresh)
- **`tea.py`** — pure builders from stored records to `libtea.models`
- **`usage.py`** — in-memory usage counters flushed to SQLite every 10 s
- **`services/`** — `pypi.py` (JSON API, wheel platform filter), `wheel_reader.py` (async range-request ZIP reader), `sbom_format.py`, `attestation.py`, `uuids.py`
- **`routes/`** — `tea.py` (all TEA endpoints), `pages.py` (HTML), `seo.py` (robots, sharded sitemap), `stats.py`

### Data model mapping

PyPI Package → TEA Product, Version → ProductRelease, Wheel file → Component+ComponentRelease, SBOM file → Artifact. All UUIDs are deterministic (UUID v5 with fixed namespace) and stored in `entities`.

### Scaling rules for changes

- Read-path queries must be index lookups or index-ordered range scans. No `OFFSET` on large tables (use `listing.pos`), no unbounded scans per request; aggregates go through `memoized()`.
- Don't write to SQLite per request from the API; buffer like `usage.py` does.
- Anything slow or upstream-dependent belongs in the worker.
- `loadtest/` has a mock PyPI, a seeder and crawler-shaped load generators for checking changes under load.

### Testing

`tests/conftest.py` provides a temp `database` fixture, a `FakePyPI` httpx transport (JSON API + range-capable wheels), and a session `tea_server` running the real app with an embedded worker against live PyPI for `libtea`'s conformance checks. 21/26 conformance checks pass; 5 CLE checks are skipped (not implemented).

## Conventions

- Ruff for linting and formatting (line length 120, Python 3.14 target)
- mypy strict mode with pydantic plugin
- `B008` ignored in ruff (FastAPI `Depends()` pattern)
- gunicorn and uvicorn-worker have no type information — see the mypy overrides in `pyproject.toml`
- Configuration via environment variables with `PYPI_TEA_` prefix

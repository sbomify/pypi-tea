# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

pypi-tea is a [Transparency Exchange API (TEA)](https://github.com/CycloneDX/transparency-exchange-api) server that extracts and serves SBOMs from PyPI package wheel files. It uses HTTP range requests to inspect wheels without downloading them fully, caches everything in Redis, and exposes TEA-compliant REST endpoints via FastAPI.

## Commands

```bash
# Install dependencies (requires Python 3.14+ and uv)
uv sync --group dev

# Run the server (requires Redis)
uv run uvicorn pypi_tea.app:app

# Run tests (uses fakeredis, no Redis needed)
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

The request flow: Client sends a TEI or PURL → route handler calls `mapper.resolve_purl()` → mapper fetches PyPI metadata via `services/pypi.py` → extracts SBOMs from wheels via `services/sbom_extractor.py` → stores UUID mappings in Redis via `cache.py` → returns TEA model objects built with `libtea.models`.

### Key layers

- **`app.py`** — FastAPI app with lifespan (creates shared httpx client + Redis cache), cache-control middleware, static dashboard
- **`config.py`** — pydantic-settings with `PYPI_TEA_` env prefix
- **`deps.py`** — FastAPI dependency injection for httpx client and cache
- **`cache.py`** — Redis wrapper: all data storage (PyPI metadata, SBOMs, negative cache, UUID lookups, stats with time-series buckets)
- **`services/mapper.py`** — Core orchestrator: resolves PURLs, coordinates caching, builds all TEA entities (Product, ProductRelease, Component, ComponentRelease, Artifact, Collection)
- **`services/pypi.py`** — PyPI JSON API client, extracts wheel URLs from metadata
- **`services/sbom_extractor.py`** — Extracts SBOM files from `.dist-info/sboms/` inside wheels using remotezip (range requests) with full-download fallback
- **`services/uuids.py`** — Deterministic UUID v5 generation for all entity types
- **`routes/`** — Thin route handlers that delegate to mapper, one file per TEA entity type

### Data model mapping

PyPI Package → TEA Product, Version → ProductRelease, Wheel file → Component+ComponentRelease, SBOM file → Artifact. All UUIDs are deterministic (UUID v5 with fixed namespace).

### Testing

Tests use `libtea`'s conformance checker against an in-process server with fakeredis. The `tea_server` fixture in `conftest.py` patches the lifespan to inject fakeredis. 21/26 conformance checks pass; 5 CLE checks are skipped (not implemented).

## Conventions

- Ruff for linting and formatting (line length 120, Python 3.14 target)
- mypy strict mode with pydantic plugin
- `B008` ignored in ruff (FastAPI `Depends()` pattern)
- `remotezip` has no type stubs — `ignore_missing_imports = true` in mypy
- Configuration via environment variables with `PYPI_TEA_` prefix

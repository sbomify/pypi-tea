# pypi-tea

A [Transparency Exchange API (TEA)](https://github.com/CycloneDX/transparency-exchange-api) server that extracts and serves SBOMs from PyPI packages.

Python wheels can include SBOMs in `.dist-info/sboms/` ([PEP 770](https://peps.python.org/pep-0770/)). pypi-tea makes these discoverable through the TEA protocol — give it a PURL like `pkg:pypi/requests@2.31.0` and it returns any SBOMs found in the package's wheel files.

## How it works

1. Client queries with a TEI or PURL identifier
2. Server resolves the package via the [PyPI JSON API](https://docs.pypi.org/api/json/)
3. Wheel files are inspected using HTTP range requests (via `remotezip`) to avoid downloading full wheels — only the ZIP central directory (~16KB) is fetched to check for `.dist-info/sboms/` entries
4. If range requests aren't supported (some CDN configurations), falls back to downloading the full wheel
5. SBOM files are extracted and mapped to TEA entities
6. Everything is cached in Redis and served as TEA-compliant responses

## Architecture

```
┌──────────┐     TEI/PURL      ┌───────────┐     JSON API     ┌─────────┐
│  Client   │ ───────────────> │  pypi-tea  │ ──────────────> │  PyPI   │
└──────────┘                   │  (FastAPI) │                  └─────────┘
                               │            │   range request   ┌─────────┐
                               │            │ ──────────────> │  Wheel  │
                               │            │   (or full GET)   │  files  │
                               │            │                   └─────────┘
                               │            │
                               │            │ <──────────────> │  Redis  │
                               └───────────┘     caching       └─────────┘
```

### Caching

All data is stored in Redis. Nothing is persisted to disk — Redis is the sole data store.

| Data | Redis key pattern | TTL | Description |
|---|---|---|---|
| PyPI metadata | `pypi:{package}:{version}` | 1 hour | JSON API response for a package version |
| SBOM content | `sbom:{wheel_url}` | 24 hours | Extracted SBOM files from a wheel (JSON array) |
| Negative cache | `neg:{wheel_url}` | 24 hours | Marker for wheels confirmed to have no SBOMs |
| UUID lookup | `uuid:{uuid}` | No expiry | Maps a deterministic UUID to entity metadata |
| Entity index | `etype:{entity_type}` | No expiry | Redis set of UUIDs per entity type (for listing) |
| Stats (totals) | `stats` | No expiry | Redis hash with cumulative hit/miss counters |
| Stats (time series) | `stats:ts:{bucket}` | 24 hours | Per-5-minute counter buckets for time-series graphs |

**Why these TTLs?**
- PyPI metadata changes when new versions are released — 1 hour keeps things reasonably fresh
- Wheel contents are immutable once published — 24 hours is conservative; SBOMs won't change
- Negative cache prevents repeatedly downloading wheels that have no SBOMs
- UUID lookups don't expire because they map deterministic UUIDs to stable data

### Statistics

The server tracks cache hit/miss ratios and SBOM availability:

- **Cache metrics**: hits and misses for PyPI metadata, SBOM content, and negative cache lookups
- **SBOM availability**: how many wheels had SBOMs vs didn't
- **Time series**: all counters are also bucketed into 5-minute intervals (24h retention) for trend visualization

Visit `GET /` for a live dashboard with charts, or `GET /stats` for raw JSON.

## Quick start

### Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)
- Redis

### Install and run

```bash
git clone https://github.com/sbomify/pypi-tea.git
cd pypi-tea
uv sync
uv run uvicorn pypi_tea.app:app
```

The server starts at `http://localhost:8000`. Visit the root URL for a live statistics dashboard.

### Configuration

All settings are configurable via environment variables with the `PYPI_TEA_` prefix:

| Variable | Default | Description |
|---|---|---|
| `PYPI_TEA_REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `PYPI_TEA_PYPI_BASE_URL` | `https://pypi.org` | PyPI API base URL |
| `PYPI_TEA_SERVER_ROOT_URL` | `http://localhost:8000` | Public root URL (used in TEA discovery responses) |
| `PYPI_TEA_TEA_SPEC_VERSION` | `0.3.0-beta.2` | TEA spec version to advertise |

## TEA endpoints

| Endpoint | Description |
|---|---|
| `GET /discovery?tei=...` | TEI-based discovery |
| `GET /products` | List or search products (`idType`, `idValue` query params) |
| `GET /product/{uuid}` | Get a product |
| `GET /product/{uuid}/releases` | List releases for a product |
| `GET /productReleases` | List or search product releases |
| `GET /productRelease/{uuid}` | Get a product release |
| `GET /productRelease/{uuid}/collection/latest` | Latest SBOM collection |
| `GET /productRelease/{uuid}/collections` | All collections |
| `GET /productRelease/{uuid}/collection/{version}` | Collection by version |
| `GET /component/{uuid}` | Get a component (wheel) |
| `GET /component/{uuid}/releases` | Component releases |
| `GET /componentRelease/{uuid}` | Get a component release with collection |
| `GET /componentRelease/{uuid}/collection/latest` | Latest collection |
| `GET /componentRelease/{uuid}/collections` | All collections |
| `GET /componentRelease/{uuid}/collection/{version}` | Collection by version |
| `GET /artifact/{uuid}` | Get an artifact (SBOM) |

### Non-TEA endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Statistics dashboard (Tailwind + Chart.js) |
| `GET /stats` | Raw statistics JSON |
| `GET /stats/timeseries` | Time-bucketed statistics (5-min intervals, 24h retention) |

## Example

Discover SBOMs for a package:

```bash
curl "http://localhost:8000/discovery?tei=urn:tei:purl:localhost:pkg:pypi/cyclonedx-python-lib@8.4.0"
```

Search by PURL:

```bash
curl "http://localhost:8000/products?idType=PURL&idValue=pkg:pypi/cyclonedx-python-lib@8.4.0"
```

## Data model

| PyPI Concept | TEA Entity | UUID derived from |
|---|---|---|
| Package (e.g. `requests`) | Product | `uuid5(NS, "pkg:pypi/requests")` |
| Version (e.g. `2.31.0`) | ProductRelease | `uuid5(NS, "pkg:pypi/requests@2.31.0")` |
| Wheel file | Component + ComponentRelease | `uuid5(NS, "wheel:<filename>")` / `uuid5(NS, <wheel_url>)` |
| SBOM file in wheel | Artifact | `uuid5(NS, "sbom:<wheel_url>:<sbom_path>")` |

All UUIDs are deterministic (UUID v5 with a fixed namespace) so they're stable across requests and server restarts.

## Deployment

A systemd service file and setup script are included in `deploy/`.

```bash
# As root:
sudo ./deploy/setup.sh
sudo systemctl start pypi-tea
```

This installs the project to `/opt/pypi-tea` (read-only) and runs as the `nobody` user. uv's cache and virtualenv are stored under `/tmp/pypi-tea` since `nobody` has no home directory and no write access to `/opt`.

To override configuration:

```bash
sudo systemctl edit pypi-tea
```

```ini
[Service]
Environment=PYPI_TEA_REDIS_URL=redis://my-redis:6379/1
Environment=PYPI_TEA_SERVER_ROOT_URL=https://tea.example.com
```

Logs:

```bash
journalctl -u pypi-tea -f
```

## Development

```bash
# Install dev dependencies
uv sync --group dev

# Run tests (uses fakeredis, no Redis required)
uv run pytest

# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format src/ tests/

# Type check
uv run mypy src/
```

### Conformance

The test suite runs [libtea's conformance checks](https://pypi.org/project/libtea/) against an in-process server. 21 of 26 checks pass; 5 CLE (Collection Lifecycle Event) checks are skipped as CLE is not implemented.

## License

MIT

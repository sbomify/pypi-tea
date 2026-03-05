# pypi-tea

A [Transparency Exchange API (TEA)](https://github.com/CycloneDX/transparency-exchange-api) server that extracts and serves SBOMs from PyPI packages.

Python wheels can include SBOMs in `.dist-info/sboms/` ([PEP 770](https://peps.python.org/pep-0770/)). pypi-tea makes these discoverable through the TEA protocol — give it a PURL like `pkg:pypi/requests@2.31.0` and it returns any SBOMs found in the package's wheel files.

## How it works

1. Client queries with a TEI or PURL identifier
2. Server resolves the package via the PyPI JSON API
3. Wheel files are inspected using HTTP range requests (via `remotezip`) to avoid downloading full wheels
4. SBOM files from `.dist-info/sboms/` are extracted and mapped to TEA entities
5. Results are cached in Redis and served as TEA-compliant responses

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
| `GET /` | Statistics dashboard |
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

All UUIDs are deterministic (UUID v5 with a fixed namespace) so they're stable across requests.

## Development

```bash
# Install dev dependencies
uv sync --group dev

# Run tests (uses fakeredis, no Redis required)
uv run pytest

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/
```

### Conformance

The test suite runs [libtea's conformance checks](https://pypi.org/project/libtea/) against an in-process server. 21 of 26 checks pass; 5 CLE (Collection Lifecycle Event) checks are skipped as CLE is not implemented.

## License

MIT

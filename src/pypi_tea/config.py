from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_path: str = "pypi-tea.db"
    pypi_base_url: str = "https://pypi.org"
    server_root_url: str = "http://localhost:8000"
    attestation_verification: bool = True

    # Read path: how long a TEA lookup for an unknown release waits for the
    # worker before answering 503, and how deep the on-demand queue may grow
    # before new lookups are shed instead of queued.
    resolve_wait_seconds: float = 20.0
    max_pending_lookups: int = 500
    # Hard ceiling on any single request; anything slower is answered 503.
    request_timeout_seconds: float = 30.0

    # pypi-tea-serve: listen address, process count (0 = one per CPU), and the
    # open-connection cap per process past which requests get an immediate 503.
    bind: str = "127.0.0.1:8000"
    web_workers: int = 0
    max_connections_per_worker: int = 512
    forwarded_allow_ips: str = "127.0.0.1"

    # Worker: concurrent ingest jobs, and per-job concurrent wheel fetches.
    worker_concurrency: int = 16
    wheel_concurrency: int = 4
    # Processes for SBOM schema validation. Validating a large CycloneDX
    # document is seconds of pure-Python CPU; run in threads it holds the GIL
    # and starves the worker's event loop until upstream connects time out.
    # 0 validates in a thread (development and tests).
    validation_processes: int = 2
    # Run the ingest worker inside the API process (development and tests only).
    embedded_worker: bool = False

    # Vulnerability scanning (pypi-tea-osv): the osv-scanner binary, how many SBOMs
    # go into one osv-scanner run, how long a run may take, and how old a scan may
    # get before the SBOM is scanned again. The OSV database changes daily; the
    # SBOMs never do.
    osv_scanner_path: str = "osv-scanner"
    osv_batch_size: int = 50
    osv_timeout_seconds: float = 600.0
    osv_rescan_hours: float = 24.0

    # Product analytics (see analytics.py). The project key is public by design:
    # the browser snippet ships it to every visitor. Set it empty to turn analytics off.
    posthog_api_key: str = "phc_pbDJTxYmvCVsafKTuQNkYCLWYf5eTXKax6tLMPMHxXeu"
    posthog_host: str = "https://us.i.posthog.com"

    model_config = {"env_prefix": "PYPI_TEA_"}


settings = Settings()

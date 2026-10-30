from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_path: str = "pypi-tea.db"
    pypi_base_url: str = "https://pypi.org"
    tea_spec_version: str = "0.3.0-beta.2"
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
    # Run the ingest worker inside the API process (development and tests only).
    embedded_worker: bool = False

    model_config = {"env_prefix": "PYPI_TEA_"}


settings = Settings()

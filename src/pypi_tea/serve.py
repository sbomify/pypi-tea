"""Production entry point: `pypi-tea-serve`.

Gunicorn supervises N uvicorn workers. Each worker binds its own SO_REUSEPORT
socket, so the kernel spreads connections across processes; with one shared
socket (`uvicorn --workers`), long-lived keep-alive connections from the edge
pile onto whichever worker accepted first. Gunicorn also kills and replaces a
worker whose event loop stops heartbeating, and recycles workers periodically.
"""

import argparse
import os
from typing import Any

from gunicorn.app.base import BaseApplication
from uvicorn_worker import UvicornWorker

from pypi_tea.config import settings


class Worker(UvicornWorker):
    # Beyond this many open connections a worker answers 503 immediately
    # instead of queueing work it can't get to in time.
    CONFIG_KWARGS: dict[str, Any] = {  # noqa: RUF012 - overrides the base class attribute
        "limit_concurrency": settings.max_connections_per_worker,
        "server_header": False,
    }


class Application(BaseApplication):
    def __init__(self, options: dict[str, Any]) -> None:
        self.options = options
        super().__init__()

    def load_config(self) -> None:
        for key, value in self.options.items():
            self.cfg.set(key, value)

    def load(self) -> Any:
        from pypi_tea.app import app

        return app


def cli() -> None:
    parser = argparse.ArgumentParser(description="Run the pypi-tea API")
    parser.add_argument("--bind", default=settings.bind)
    # process_cpu_count honours cpusets, so inside a container it reports the CPUs
    # actually granted rather than every CPU on the host.
    parser.add_argument("--workers", type=int, default=settings.web_workers or os.process_cpu_count() or 2)
    args = parser.parse_args()
    Application(
        {
            "bind": args.bind,
            "workers": args.workers,
            "worker_class": "pypi_tea.serve.Worker",
            "reuse_port": True,
            "backlog": 2048,
            "timeout": 60,
            "graceful_timeout": 20,
            "keepalive": 5,
            "max_requests": 50_000,
            "max_requests_jitter": 5_000,
            "forwarded_allow_ips": settings.forwarded_allow_ips,
            "accesslog": None,
            "errorlog": "-",
        }
    ).run()


if __name__ == "__main__":
    cli()

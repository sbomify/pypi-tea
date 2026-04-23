"""Tests for systemd watchdog integration (src/pypi_tea/app.py)."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

import fakeredis.aioredis
import pytest
import sdnotify
from fastapi import FastAPI

import pypi_tea.app as app_module
from pypi_tea.app import _maybe_start_watchdog, lifespan


class FakeNotifier:
    """Records notify() calls for assertion in tests."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def notify(self, msg: str) -> None:
        self.messages.append(msg)


@asynccontextmanager
async def _patched_lifespan(monkeypatch: pytest.MonkeyPatch, notifier: FakeNotifier) -> AsyncIterator[FastAPI]:
    """Run the real lifespan with heavy deps stubbed for isolated testing."""
    from pypi_tea.cache import Cache

    monkeypatch.setattr(sdnotify, "SystemdNotifier", lambda: notifier)
    monkeypatch.setattr(app_module, "_init_extraction_pool", lambda: None)
    monkeypatch.setattr(app_module, "_shutdown_extraction_pool", lambda: None)

    async def fake_init(self: Cache) -> None:
        self._r = fakeredis.aioredis.FakeRedis(decode_responses=True)

    monkeypatch.setattr(Cache, "init", fake_init)

    app = FastAPI()
    async with lifespan(app):
        yield app


@pytest.mark.anyio()
async def test_watchdog_sends_ready_and_periodic_pings(monkeypatch: pytest.MonkeyPatch) -> None:
    """With NOTIFY_SOCKET + WATCHDOG_USEC set, READY=1 fires once and WATCHDOG=1 fires repeatedly."""
    notifier = FakeNotifier()
    monkeypatch.setenv("NOTIFY_SOCKET", "/tmp/fake-notify")
    monkeypatch.setenv("WATCHDOG_USEC", "200000")  # 0.2s → ping every 0.1s
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid()))

    async with _patched_lifespan(monkeypatch, notifier):
        assert notifier.messages[0] == "READY=1"
        await asyncio.sleep(0.35)  # allow 3+ pings at 0.1s interval

    watchdog_pings = sum(1 for m in notifier.messages if m == "WATCHDOG=1")
    assert watchdog_pings >= 2, f"expected ≥2 WATCHDOG=1 pings, got {watchdog_pings}: {notifier.messages}"


@pytest.mark.anyio()
async def test_no_notify_socket_skips_watchdog(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without NOTIFY_SOCKET, the sd_notify path is entirely skipped."""
    notifier = FakeNotifier()
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)

    async with _patched_lifespan(monkeypatch, notifier):
        pass

    assert notifier.messages == []


def test_maybe_start_watchdog_invalid_usec_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-integer WATCHDOG_USEC disables the watchdog (logs warning, returns None)."""
    monkeypatch.setenv("WATCHDOG_USEC", "not-a-number")
    monkeypatch.delenv("WATCHDOG_PID", raising=False)
    assert _maybe_start_watchdog(cast(sdnotify.SystemdNotifier, FakeNotifier())) is None


def test_maybe_start_watchdog_pid_mismatch_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    """WATCHDOG_PID not matching current pid disables the watchdog — pings would be ignored anyway."""
    monkeypatch.setenv("WATCHDOG_USEC", "30000000")
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid() + 99999))
    assert _maybe_start_watchdog(cast(sdnotify.SystemdNotifier, FakeNotifier())) is None


def test_maybe_start_watchdog_zero_usec_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    """WATCHDOG_USEC=0 (the default when WatchdogSec is not configured) disables the watchdog."""
    monkeypatch.setenv("WATCHDOG_USEC", "0")
    monkeypatch.delenv("WATCHDOG_PID", raising=False)
    assert _maybe_start_watchdog(cast(sdnotify.SystemdNotifier, FakeNotifier())) is None

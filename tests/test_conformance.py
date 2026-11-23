from typing import Any

import pytest
from libtea.conformance._checks import ALL_CHECKS, CheckContext
from libtea.conformance._types import CheckStatus
from libtea.discovery import purl_tei

PURL = "pkg:pypi/libtea@0.4.0"


@pytest.fixture(scope="module")
def check_context(tea_client: Any) -> CheckContext:
    """One context per TEA version: checks record UUIDs in it for the checks after them."""
    return CheckContext(tei=f"urn:tei:purl:localhost:{PURL}" if tea_client.is_legacy else purl_tei("localhost", PURL))


@pytest.mark.parametrize("check_fn", ALL_CHECKS, ids=[fn.__name__ for fn in ALL_CHECKS])
def test_tea_conformance(tea_client: Any, check_context: CheckContext, check_fn: Any) -> None:
    result = check_fn(tea_client, check_context)
    if result.status == CheckStatus.SKIP:
        pytest.skip(result.message)
    elif result.status == CheckStatus.FAIL:
        pytest.fail(f"{result.name}: {result.message}")

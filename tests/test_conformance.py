from typing import Any

import pytest
from libtea.conformance._checks import ALL_CHECKS, CheckContext
from libtea.conformance._types import CheckStatus
from libtea.discovery import purl_tei

TEI = purl_tei("localhost", "pkg:pypi/libtea@0.4.0")
# PyPI publishes no lifecycle data, so the CLE checks are the only ones allowed to skip.
CLE_CHECKS = {"product_cle", "product_release_cle", "component_cle", "component_release_cle", "cle_event_ordering"}


@pytest.fixture(scope="module")
def check_context(tea_client: Any) -> CheckContext:
    # A second product, so pagination_token has a next page to follow.
    tea_client.discover(purl="pkg:pypi/packageurl-python@0.16.0")
    return CheckContext(tei=TEI)


@pytest.mark.parametrize("check_fn", ALL_CHECKS, ids=[fn.__name__ for fn in ALL_CHECKS])
def test_tea_conformance(tea_client: Any, check_context: CheckContext, check_fn: Any) -> None:
    result = check_fn(tea_client, check_context)
    if result.status == CheckStatus.SKIP and result.name in CLE_CHECKS:
        pytest.skip(result.message)
    assert result.status == CheckStatus.PASS, f"{result.name}: {result.status} {result.message}"

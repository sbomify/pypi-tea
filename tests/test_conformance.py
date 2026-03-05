import pytest
from libtea.conformance._checks import ALL_CHECKS, CheckContext
from libtea.conformance._types import CheckStatus

TEI = "urn:tei:purl:localhost:pkg:pypi/libtea@0.4.0"


@pytest.fixture(scope="session")
def check_context():
    return CheckContext(tei=TEI)


@pytest.mark.parametrize("check_fn", ALL_CHECKS, ids=[fn.__name__ for fn in ALL_CHECKS])
def test_tea_conformance(tea_client, check_context, check_fn):
    result = check_fn(tea_client, check_context)
    if result.status == CheckStatus.SKIP:
        pytest.skip(result.message)
    elif result.status == CheckStatus.FAIL:
        pytest.fail(f"{result.name}: {result.message}")

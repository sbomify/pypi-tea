from pypi_tea.services.mapper import PurlQualifiers, parse_purl
from pypi_tea.services.pypi import WheelInfo, filter_wheels_by_platform

WHEELS = [
    WheelInfo(
        filename="numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        url="https://files.pythonhosted.org/numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.whl",
        digests={"sha256": "aaa"},
        size=1000,
    ),
    WheelInfo(
        filename="numpy-1.26.0-cp311-cp311-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        url="https://files.pythonhosted.org/numpy-1.26.0-cp311-cp311-manylinux_2_17_aarch64.whl",
        digests={"sha256": "bbb"},
        size=1000,
    ),
    WheelInfo(
        filename="numpy-1.26.0-cp311-cp311-macosx_11_0_arm64.whl",
        url="https://files.pythonhosted.org/numpy-1.26.0-cp311-cp311-macosx_11_0_arm64.whl",
        digests={"sha256": "ccc"},
        size=1000,
    ),
    WheelInfo(
        filename="numpy-1.26.0-cp311-cp311-win_amd64.whl",
        url="https://files.pythonhosted.org/numpy-1.26.0-cp311-cp311-win_amd64.whl",
        digests={"sha256": "ddd"},
        size=1000,
    ),
    WheelInfo(
        filename="requests-2.31.0-py3-none-any.whl",
        url="https://files.pythonhosted.org/requests-2.31.0-py3-none-any.whl",
        digests={"sha256": "eee"},
        size=500,
    ),
]


def test_no_filter_returns_all():
    result = filter_wheels_by_platform(WHEELS)
    assert len(result) == len(WHEELS)


def test_os_linux_filters_correctly():
    result = filter_wheels_by_platform(WHEELS, os_filter="linux")
    filenames = [w.filename for w in result]
    assert any("manylinux" in f for f in filenames)
    assert any("any" in f for f in filenames)
    assert not any("macosx" in f for f in filenames)
    assert not any("win" in f for f in filenames)
    assert len(result) == 3  # 2 linux + 1 any


def test_os_darwin_alias():
    result = filter_wheels_by_platform(WHEELS, os_filter="darwin")
    filenames = [w.filename for w in result]
    assert any("macosx" in f for f in filenames)
    assert any("any" in f for f in filenames)
    assert len(result) == 2  # 1 macosx + 1 any


def test_os_windows():
    result = filter_wheels_by_platform(WHEELS, os_filter="windows")
    filenames = [w.filename for w in result]
    assert any("win" in f for f in filenames)
    assert any("any" in f for f in filenames)
    assert len(result) == 2  # 1 win + 1 any


def test_arch_x86_64():
    result = filter_wheels_by_platform(WHEELS, arch_filter="x86_64")
    filenames = [w.filename for w in result]
    assert any("x86_64" in f or "amd64" in f for f in filenames)
    assert any("any" in f for f in filenames)
    # linux x86_64 + win_amd64 + any
    assert len(result) == 3


def test_arch_amd64_alias():
    result = filter_wheels_by_platform(WHEELS, arch_filter="amd64")
    filenames = [w.filename for w in result]
    assert any("x86_64" in f or "amd64" in f for f in filenames)
    assert len(result) == 3


def test_arch_arm64():
    result = filter_wheels_by_platform(WHEELS, arch_filter="arm64")
    filenames = [w.filename for w in result]
    assert any("aarch64" in f or "arm64" in f for f in filenames)
    assert any("any" in f for f in filenames)
    # linux aarch64 + macosx arm64 + any
    assert len(result) == 3


def test_os_and_arch_combined():
    result = filter_wheels_by_platform(WHEELS, os_filter="linux", arch_filter="aarch64")
    filenames = [w.filename for w in result]
    assert len(result) == 2  # linux aarch64 + any
    assert any("aarch64" in f for f in filenames)
    assert any("any" in f for f in filenames)


def test_os_and_arch_no_match():
    result = filter_wheels_by_platform(WHEELS, os_filter="windows", arch_filter="aarch64")
    # Only the pure-python wheel matches
    assert len(result) == 1
    assert "any" in result[0].filename


def test_pure_python_always_included():
    pure = [WHEELS[-1]]  # requests any
    result = filter_wheels_by_platform(pure, os_filter="linux", arch_filter="x86_64")
    assert len(result) == 1


def test_unparseable_filename_included_as_fallback():
    wheels = [
        WheelInfo(filename="weird-package.whl", url="https://example.com/weird.whl", digests={}, size=100),
        WHEELS[0],  # linux x86_64
    ]
    result = filter_wheels_by_platform(wheels, os_filter="windows")
    filenames = [w.filename for w in result]
    assert "weird-package.whl" in filenames
    assert len(result) == 1  # only the unparseable one, not linux


def test_parse_purl_without_qualifiers():
    name, version, qualifiers = parse_purl("pkg:pypi/requests@2.31.0")
    assert name == "requests"
    assert version == "2.31.0"
    assert qualifiers == PurlQualifiers(os_name=None, arch=None)


def test_parse_purl_with_os_qualifier():
    name, version, qualifiers = parse_purl("pkg:pypi/numpy@1.26.0?os=linux")
    assert name == "numpy"
    assert version == "1.26.0"
    assert qualifiers.os_name == "linux"
    assert qualifiers.arch is None


def test_parse_purl_with_both_qualifiers():
    name, version, qualifiers = parse_purl("pkg:pypi/numpy@1.26.0?os=linux&arch=x86_64")
    assert name == "numpy"
    assert version == "1.26.0"
    assert qualifiers.os_name == "linux"
    assert qualifiers.arch == "x86_64"

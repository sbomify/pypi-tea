"""Content-based SBOM format detection and validation.

PEP 770 is format-agnostic — any file in .dist-info/sboms/ is valid.
We detect the format and version by parsing the actual content, never
by relying on file extensions.
"""

import json
import logging
import os
import tempfile
from xml.etree import ElementTree as ET

from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator

logger = logging.getLogger("pypi_tea.sbom_format")

_CDX_SCHEMA_MAP: dict[str, SchemaVersion] = {
    "1.0": SchemaVersion.V1_0,
    "1.1": SchemaVersion.V1_1,
    "1.2": SchemaVersion.V1_2,
    "1.3": SchemaVersion.V1_3,
    "1.4": SchemaVersion.V1_4,
    "1.5": SchemaVersion.V1_5,
    "1.6": SchemaVersion.V1_6,
    "1.7": SchemaVersion.V1_7,
}


def detect_sbom_format(content: str) -> tuple[str | None, str | None]:
    """Detect SBOM format and version from file content.

    Returns (format_string, media_type) where format_string is e.g.
    'CycloneDX/1.6' or 'SPDX/2.3', and media_type is the appropriate
    IANA media type. Returns (None, None) if unrecognized.
    """
    # Try JSON-based formats first (most common)
    result = _detect_json(content)
    if result[0] is not None:
        return result

    # Try XML-based formats
    result = _detect_xml(content)
    if result[0] is not None:
        return result

    # Try SPDX tag-value format
    result = _detect_spdx_tv(content)
    if result[0] is not None:
        return result

    return None, None


def _detect_json(content: str) -> tuple[str | None, str | None]:
    """Detect CycloneDX JSON or SPDX JSON from content."""
    stripped = content.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return None, None

    try:
        data = json.loads(content)
    except json.JSONDecodeError, ValueError:
        return None, None

    if not isinstance(data, dict):
        return None, None

    # CycloneDX JSON: has bomFormat field
    if data.get("bomFormat") == "CycloneDX":
        version = data.get("specVersion", "unknown")
        return f"CycloneDX/{version}", "application/vnd.cyclonedx+json"

    # SPDX 2.x JSON: has spdxVersion field
    spdx_version = data.get("spdxVersion", "")
    if isinstance(spdx_version, str) and spdx_version.startswith("SPDX-"):
        version = spdx_version.removeprefix("SPDX-") or "unknown"
        return f"SPDX/{version}", "application/spdx+json"

    # SPDX 3.x JSON: has @graph with spdxVersion or type containing "SpdxDocument"
    if "@graph" in data or data.get("type") == "SpdxDocument":
        version = data.get("spdxVersion", "3.0")
        if isinstance(version, str) and version.startswith("SPDX-"):
            version = version.removeprefix("SPDX-")
        return f"SPDX/{version}", "application/spdx+json"

    return None, None


def _detect_xml(content: str) -> tuple[str | None, str | None]:
    """Detect CycloneDX XML or SPDX RDF/XML from content."""
    stripped = content.lstrip()
    if not stripped.startswith("<"):
        return None, None

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None, None

    tag = root.tag

    # CycloneDX XML: namespace is http://cyclonedx.org/schema/bom/<version>
    if "cyclonedx.org/schema/bom/" in tag:
        ns = tag.split("}")[0].lstrip("{") if "}" in tag else ""
        version = ns.rsplit("/", 1)[-1] if "/" in ns else "unknown"
        return f"CycloneDX/{version}", "application/vnd.cyclonedx+xml"

    # Also match if root element is "bom" with a cyclonedx namespace attribute
    if tag == "bom" or tag.endswith("}bom"):
        for _key, value in root.attrib.items():
            if "cyclonedx.org" in value:
                return "CycloneDX/unknown", "application/vnd.cyclonedx+xml"

    # SPDX RDF/XML: namespace contains spdx.org
    if "spdx.org" in tag:
        return "SPDX/unknown", "application/spdx+rdf"

    # Check child elements for SPDX RDF
    for child in root:
        if "spdx.org" in child.tag:
            return "SPDX/unknown", "application/spdx+rdf"

    return None, None


def _detect_spdx_tv(content: str) -> tuple[str | None, str | None]:
    """Detect SPDX tag-value format from content."""
    for line in content.splitlines()[:20]:
        line = line.strip()
        if line.startswith("SPDXVersion:"):
            version_str = line.split(":", 1)[1].strip()
            version = version_str.removeprefix("SPDX-") or "unknown"
            return f"SPDX/{version}", "text/spdx"
    return None, None


def validate_sbom(content: str, fmt: str, media_type: str) -> bool:
    """Validate SBOM content against its schema.

    Returns True if valid, False if validation fails or is not possible.
    """
    if fmt.startswith("CycloneDX/"):
        return _validate_cdx(content, fmt, media_type)
    if fmt.startswith("SPDX/"):
        return _validate_spdx(content, media_type)
    return False


def _validate_cdx(content: str, fmt: str, media_type: str) -> bool:
    version = fmt.removeprefix("CycloneDX/")
    schema_version = _CDX_SCHEMA_MAP.get(version)
    if schema_version is None:
        logger.warning("No CDX schema for version %s", version)
        return False

    if "json" in media_type:
        output_fmt = OutputFormat.JSON
    elif "xml" in media_type:
        output_fmt = OutputFormat.XML
    else:
        logger.warning("Unsupported CDX media type for validation: %s", media_type)
        return False

    try:
        validator = make_schemabased_validator(output_fmt, schema_version)
        error = validator.validate_str(content)
        if error is not None:
            logger.info("CDX validation failed for %s: %s", fmt, str(error)[:200])
            return False
        return True
    except Exception:
        logger.exception("CDX validation error for %s", fmt)
        return False


def _validate_spdx(content: str, media_type: str) -> bool:
    if "json" not in media_type:
        # spdx-tools only reliably validates JSON via file; skip others
        return True

    try:
        from spdx_tools.spdx.parser.parse_anything import parse_file
        from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

        fd, tmp = tempfile.mkstemp(suffix=".spdx.json")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            doc = parse_file(tmp)
            errors = validate_full_spdx_document(doc)
            if errors:
                logger.info("SPDX validation found %d error(s): %s", len(errors), errors[0].validation_message)
                return False
            return True
        finally:
            os.unlink(tmp)
    except Exception:
        logger.exception("SPDX validation error")
        return False

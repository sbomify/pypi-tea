# SBOM for {{ name }} {{ version }}

{% if summary %}
> {{ summary | md(500) }}

{% endif %}
The Python package {{ name }} {{ version }} ships {{ sbom_count }} SBOM file{{ "s" if sbom_count != 1 }} ({{ formats | join(", ") }}) inside its wheels, under `.dist-info/sboms/` ([PEP 770](https://peps.python.org/pep-0770/)).
{%- if has_attestation %} Its wheels carry a verified PEP 740 attestation.{% endif %}


- Package URL (PURL): `{{ purl }}`
- PyPI: https://pypi.org/project/{{ name }}/{{ version }}/
{% if author %}
- Author: {{ author | md(200) }}
{% endif %}
{% if license %}
- License: {{ license | md(200) }}
{% endif %}
{% if requires_python %}
- Requires Python: {{ requires_python | md }}
{% endif %}
{% for label, url in project_urls.items() %}
- {{ label | md(100) }}: <{{ url | md_url }}>
{% endfor %}

## SBOMs

{% for wheel in wheels %}
### {{ wheel.filename | md }}

{% if wheel.attestation and wheel.attestation.status == "verified" %}
PEP 740 attestation verified{% if wheel.attestation.publisher_kind %} ({{ wheel.attestation.publisher_kind | md }}{% if wheel.attestation.repository %}, {{ wheel.attestation.repository | md }}{% endif %}{% if wheel.attestation.workflow %}, workflow {{ wheel.attestation.workflow | md }}{% endif %}){% endif %}.

{% elif wheel.attestation and wheel.attestation.status == "failed" %}
PEP 740 attestation failed verification{% if wheel.attestation.error %}: {{ wheel.attestation.error | md(300) }}{% endif %}.

{% endif %}
{% for sbom in wheel.sboms %}
- [{{ sbom.path | md }}]({{ sbom.download_url_abs }}): {{ sbom.format or "unknown format" }}, `{{ sbom.media_type }}`, {% if sbom.valid is none %}not validated{% elif sbom.valid %}valid{% else %}fails schema validation{% endif %}

{% endfor %}

{% endfor %}
## Fetch it over TEA

This SBOM is served over the [Transparency Exchange API](https://github.com/CycloneDX/transparency-exchange-api) (TEA). With the `libtea` client:

```
pip install libtea
python -m libtea {{ server_root_url }} {{ purl }}
```

Machine-readable copy of this page: {{ canonical_url }}.json

---
From pypi-tea by sbomify: {{ canonical_url }}

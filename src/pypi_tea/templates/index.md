# SBOM coverage across PyPI

pypi-tea tracks which Python packages ship a CycloneDX or SPDX SBOM inside their wheels ([PEP 770](https://peps.python.org/pep-0770/)), whether it validates, and whether the wheel carries a PEP 740 attestation. Every SBOM found is served over the [Transparency Exchange API](https://github.com/CycloneDX/transparency-exchange-api) (TEA). Every page is also available as Markdown: add `.md` to its URL.

## Coverage

- Package versions explored: {{ "{:,}".format(stats.packages.total_explored) }}
- With an SBOM: {{ "{:,}".format(stats.packages.with_sbom) }}{% if stats.packages.sbom_percentage is not none %} ({{ stats.packages.sbom_percentage }}%){% endif %}

- Wheels checked: {{ "{:,}".format(stats.wheels.total_checked) }}, of which {{ "{:,}".format(stats.wheels.with_sbom) }} contain an SBOM
{% if stats.attestations.verified %}
- Wheels with a verified PEP 740 attestation: {{ "{:,}".format(stats.attestations.verified) }}
{% endif %}
{% if stats.sbom_formats %}
- SBOM formats: {% for fmt, n in stats.sbom_formats | dictsort(by="value", reverse=true) %}{{ fmt }} ({{ "{:,}".format(n) }}){% if not loop.last %}, {% endif %}{% endfor %}

{% endif %}

## Browse

- [All packages with SBOMs]({{ server_root_url }}/packages.md)
- [CycloneDX SBOMs]({{ server_root_url }}/packages.md?format=CycloneDX)
- [SPDX SBOMs]({{ server_root_url }}/packages.md?format=SPDX)

## Query with TEA

```
pip install libtea
python -m libtea {{ server_root_url }} pkg:pypi/<name>@<version>
```

A release that hasn't been looked up before is fetched from PyPI on the first TEA query.

---
From pypi-tea by sbomify: {{ server_root_url }}/

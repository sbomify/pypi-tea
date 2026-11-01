# {% if active_format %}{{ active_format }} SBOMs{% else %}PyPI packages with SBOMs{% endif %}


{{ "{:,}".format(total) }} Python package{{ "s" if total != 1 }} on PyPI ship{{ "s" if total == 1 }} {% if active_format %}a {{ active_format }}{% else %}an{% endif %} SBOM inside {{ "its" if total == 1 else "their" }} wheels. Page {{ page }} of {{ total_pages }}; each package links to its page, and adding `.md` to that URL gives the page as Markdown.

{% for pkg in packages %}
- [{{ pkg.name }} {{ pkg.version }}]({{ server_root_url }}/package/{{ pkg.name }}/{{ pkg.version }}): {{ pkg.formats | join(", ") }}
{% endfor %}

{% if prev_query or next_query %}
{% if prev_query %}
- Previous page: {{ server_root_url }}/packages.md{{ prev_query }}
{% endif %}
{% if next_query %}
- Next page: {{ server_root_url }}/packages.md{{ next_query }}
{% endif %}

{% endif %}
---
From pypi-tea by sbomify: {{ canonical_url }}

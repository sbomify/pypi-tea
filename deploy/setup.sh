#!/usr/bin/env bash
set -euo pipefail

# Install pypi-tea into /opt/pypi-tea and enable its systemd services.
# Run as root. Usage: ./setup.sh [VERSION]   (default: latest release on PyPI)

VERSION="${1:-}"
UV_MIN_VERSION="0.13.4"
uv_current="$(uv --version 2>/dev/null | awk '{print $2}' || true)"
if [ -z "$uv_current" ] || [ "$(printf '%s\n%s\n' "$UV_MIN_VERSION" "$uv_current" | sort -V | head -n1)" != "$UV_MIN_VERSION" ]; then
    echo "==> Installing uv ${UV_MIN_VERSION} (found: ${uv_current:-none})"
    curl -LsSf "https://astral.sh/uv/${UV_MIN_VERSION}/install.sh" | sh
    cp ~/.local/bin/uv ~/.local/bin/uvx /usr/local/bin/
fi

if ! id pypi-tea &>/dev/null; then
    echo "==> Creating pypi-tea user"
    useradd --system --no-create-home --shell /usr/sbin/nologin pypi-tea
fi

# Install once into a fixed venv. Services start from it directly, so a restart
# never depends on PyPI being reachable.
echo "==> Installing pypi-tea${VERSION:+==$VERSION} into /opt/pypi-tea"
UV_PYTHON_INSTALL_DIR=/opt/pypi-tea-python uv venv --python 3.14 --allow-existing /opt/pypi-tea
uv pip install --python /opt/pypi-tea/bin/python "pypi-tea${VERSION:+==$VERSION}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "==> Installing systemd services"
cp "${SCRIPT_DIR}/pypi-tea.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/pypi-tea-worker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pypi-tea pypi-tea-worker

echo "==> Done. Set PYPI_TEA_SERVER_ROOT_URL in /etc/default/pypi-tea, then:"
echo "    systemctl restart pypi-tea pypi-tea-worker"

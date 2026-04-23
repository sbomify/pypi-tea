#!/usr/bin/env bash
set -euo pipefail

# Install pypi-tea systemd service.
# Run as root.

# Install uv if not present
if ! command -v uv &>/dev/null; then
    echo "==> Installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    cp ~/.local/bin/uv /usr/local/bin/uv
fi

# Create dedicated service user (no home dir, no login)
if ! id pypi-tea &>/dev/null; then
    echo "==> Creating pypi-tea user"
    useradd --system --no-create-home --shell /usr/sbin/nologin pypi-tea
fi

# Create writable dir for uvx cache and tool installs
mkdir -p /tmp/pypi-tea
chown pypi-tea:pypi-tea /tmp/pypi-tea

# Install systemd services
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "==> Installing systemd services"
cp "${SCRIPT_DIR}/pypi-tea.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/pypi-tea-worker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pypi-tea pypi-tea-worker

echo "==> Done. Start with:"
echo "    systemctl start pypi-tea pypi-tea-worker"
echo ""
echo "    Logs:"
echo "    journalctl -u pypi-tea -f"
echo "    journalctl -u pypi-tea-worker -f"
echo ""
echo "    Configure via environment overrides:"
echo "    systemctl edit pypi-tea"
echo "    systemctl edit pypi-tea-worker"

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

# Create cache dir for uvx (nobody needs write access here)
mkdir -p /tmp/pypi-tea-cache
chown nobody:nogroup /tmp/pypi-tea-cache

# Install systemd service
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "==> Installing systemd service"
cp "${SCRIPT_DIR}/pypi-tea.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pypi-tea

echo "==> Done. Start with: systemctl start pypi-tea"
echo "    Logs: journalctl -u pypi-tea -f"
echo ""
echo "    Configure via environment overrides:"
echo "    systemctl edit pypi-tea"

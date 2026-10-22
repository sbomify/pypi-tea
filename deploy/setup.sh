#!/usr/bin/env bash
set -euo pipefail

# Install pypi-tea systemd service.
# Run as root.

# Install uv, or upgrade it if it's older than UV_MIN_VERSION. uv < 0.13.4
# still trusts the compromised emSign CAs, and the service fetches
# pypi-tea@latest through uvx on every start.
UV_MIN_VERSION="0.13.4"
uv_current="$(uv --version 2>/dev/null | awk '{print $2}' || true)"
if [ -z "$uv_current" ] || [ "$(printf '%s\n%s\n' "$UV_MIN_VERSION" "$uv_current" | sort -V | head -n1)" != "$UV_MIN_VERSION" ]; then
    echo "==> Installing uv ${UV_MIN_VERSION} (found: ${uv_current:-none})"
    curl -LsSf "https://astral.sh/uv/${UV_MIN_VERSION}/install.sh" | sh
    cp ~/.local/bin/uv ~/.local/bin/uvx /usr/local/bin/
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

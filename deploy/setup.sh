#!/usr/bin/env bash
set -euo pipefail

# Deploy pypi-tea to /opt/pypi-tea and install the systemd service.
# Run as root.

INSTALL_DIR=/opt/pypi-tea
TMP_DIR=/tmp/pypi-tea
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Installing pypi-tea to ${INSTALL_DIR}"

# Copy project files (nobody only needs read access)
mkdir -p "${INSTALL_DIR}"
cp -r "${REPO_DIR}/src" "${INSTALL_DIR}/"
cp "${REPO_DIR}/pyproject.toml" "${INSTALL_DIR}/"
cp "${REPO_DIR}/uv.lock" "${INSTALL_DIR}/"

# Create writable tmp directory for uv cache and venv
mkdir -p "${TMP_DIR}"
chown nobody:nogroup "${TMP_DIR}"

# Install uv if not present
if ! command -v uv &>/dev/null; then
    echo "==> Installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # uv installs to ~/.local/bin by default; copy to system path
    cp ~/.local/bin/uv /usr/local/bin/uv
fi

# Install systemd service
echo "==> Installing systemd service"
cp "${REPO_DIR}/deploy/pypi-tea.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pypi-tea

echo "==> Done. Start with: systemctl start pypi-tea"
echo "    Logs: journalctl -u pypi-tea -f"
echo ""
echo "    Configure via environment overrides in:"
echo "    systemctl edit pypi-tea"

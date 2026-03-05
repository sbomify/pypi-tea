#!/usr/bin/env bash
set -euo pipefail

# Deploy pypi-tea to /opt/pypi-tea and install the systemd service.
# Run as root.

INSTALL_DIR=/opt/pypi-tea
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Install uv if not present
if ! command -v uv &>/dev/null; then
    echo "==> Installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    cp ~/.local/bin/uv /usr/local/bin/uv
fi

echo "==> Installing pypi-tea to ${INSTALL_DIR}"

# Copy project files
mkdir -p "${INSTALL_DIR}"
cp -r "${REPO_DIR}/src" "${INSTALL_DIR}/"
cp "${REPO_DIR}/pyproject.toml" "${INSTALL_DIR}/"
cp "${REPO_DIR}/uv.lock" "${INSTALL_DIR}/"
cp "${REPO_DIR}/README.md" "${INSTALL_DIR}/"

# Build the venv as root so nobody never needs write access
echo "==> Building virtualenv"
cd "${INSTALL_DIR}"
uv sync --locked --no-editable

# Lock everything down — nobody gets read+execute only
chown -R root:nogroup "${INSTALL_DIR}"
chmod -R o+rX "${INSTALL_DIR}"
chmod -R o-w "${INSTALL_DIR}"

# Install systemd service
echo "==> Installing systemd service"
cp "${REPO_DIR}/deploy/pypi-tea.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pypi-tea

echo "==> Done. Start with: systemctl start pypi-tea"
echo "    Logs: journalctl -u pypi-tea -f"
echo ""
echo "    Configure via environment overrides:"
echo "    systemctl edit pypi-tea"
echo ""
echo "    To update, re-run this script after pulling new code."

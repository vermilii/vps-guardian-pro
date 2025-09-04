
#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="vps-guardian"
INSTALL_DIR="/opt/vps-guardian"

if [[ "$EUID" -ne 0 ]]; then
  echo "Harus dijalankan sebagai root."
  exit 1
fi

systemctl stop "${SERVICE_NAME}" || true
systemctl disable "${SERVICE_NAME}" || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload || true
rm -rf "${INSTALL_DIR}"

echo "Selesai uninstall."

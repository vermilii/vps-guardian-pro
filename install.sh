
#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/vps-guardian"
SERVICE_NAME="vps-guardian"

need_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "Harus dijalankan sebagai root."
    exit 1
  fi
}

detect_pkg() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  else
    echo "unknown"
  fi
}

prompt_if_empty() {
  local varname="$1"
  local prompt="$2"
  local -n ref="$varname"
  if [[ -z "${ref:-}" ]]; then
    read -rp "$prompt: " ref
  fi
}

yesno_default() {
  local var="${1:-}"
  local def="${2:-n}"
  if [[ -z "${var}" ]]; then
    echo "$def"
  else
    echo "$var"
  fi
}

need_root

PKG_MGR=$(detect_pkg)
echo "Paket manager: $PKG_MGR"

# Install deps
if [[ "$PKG_MGR" == "apt" ]]; then
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip curl jq coreutils sed grep gawk systemd nftables iptables rsync
  # Optional: fail2ban decision later
elif [[ "$PKG_MGR" == "dnf" ]]; then
  dnf install -y python3 python3-virtualenv python3-pip curl jq coreutils sed gawk systemd nftables iptables rsync
elif [[ "$PKG_MGR" == "yum" ]]; then
  yum install -y python3 python3-virtualenv python3-pip curl jq coreutils sed gawk systemd nftables iptables rsync
else
  echo "Tidak dapat mendeteksi package manager."
  exit 1
fi

# Copy files
mkdir -p "$INSTALL_DIR"
rsync -a --delete "$REPO_DIR/" "$INSTALL_DIR/" 2>/dev/null || cp -r "$REPO_DIR"/* "$INSTALL_DIR"/

cd "$INSTALL_DIR"

# Python venv
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

# Telegram config
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
prompt_if_empty TELEGRAM_BOT_TOKEN "Masukkan TELEGRAM_BOT_TOKEN"
prompt_if_empty TELEGRAM_CHAT_ID "Masukkan TELEGRAM_CHAT_ID"

# Optional toggles via env or prompt
PROM_ENABLE="$(yesno_default "${PROM_ENABLE:-}" y)"
PROM_PORT="${PROM_PORT:-9877}"
INSTALL_FAIL2BAN="$(yesno_default "${INSTALL_FAIL2BAN:-}" n)"
FAIL2BAN_JAIL="${FAIL2BAN_JAIL:-sshd}"
CF_ENABLED="$(yesno_default "${CF_ENABLED:-}" n)"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}"

read -rp "Aktifkan Prometheus exporter? (y/N) [${PROM_ENABLE}]: " in_prom || true
PROM_ENABLE="${in_prom:-$PROM_ENABLE}"
if [[ "${PROM_ENABLE,,}" == "y" ]]; then
  read -rp "Port Prometheus [${PROM_PORT}]: " in_port || true
  PROM_PORT="${in_port:-$PROM_PORT}"
fi

read -rp "Install & aktifkan Fail2ban? (y/N) [${INSTALL_FAIL2BAN}]: " in_f2b || true
INSTALL_FAIL2BAN="${in_f2b:-$INSTALL_FAIL2BAN}"
if [[ "${INSTALL_FAIL2BAN,,}" == "y" ]]; then
  read -rp "Nama jail Fail2ban [${FAIL2BAN_JAIL}]: " in_jail || true
  FAIL2BAN_JAIL="${in_jail:-$FAIL2BAN_JAIL}"
fi

read -rp "Aktifkan integrasi Cloudflare? (y/N) [${CF_ENABLED}]: " in_cf || true
CF_ENABLED="${in_cf:-$CF_ENABLED}"
if [[ "${CF_ENABLED,,}" == "y" ]]; then
  prompt_if_empty CF_API_TOKEN "Masukkan CF_API_TOKEN"
  prompt_if_empty CF_ZONE_ID "Masukkan CF_ZONE_ID"
fi

# Apply config.yaml changes
sed -ri "s|PUT_YOUR_TELEGRAM_BOT_TOKEN_HERE|${TELEGRAM_BOT_TOKEN}|g" config.yaml
sed -ri "s|PUT_YOUR_TELEGRAM_CHAT_ID_HERE|${TELEGRAM_CHAT_ID}|g" config.yaml
# Prometheus
if [[ "${PROM_ENABLE,,}" == "y" ]]; then
  sed -ri 's|prometheus:\n\s*enable: false|prometheus:\n  enable: true|g' config.yaml || true
  sed -ri "s|(prometheus:\n\s*enable:).*|\1 true|g" config.yaml
  sed -ri "s|(port:).*|\1 ${PROM_PORT}|g" config.yaml
else
  sed -ri "s|(prometheus:\n\s*enable:).*|\1 false|g" config.yaml
fi
# Fail2ban
if [[ "${INSTALL_FAIL2BAN,,}" == "y" ]]; then
  if [[ "$PKG_MGR" == "apt" ]]; then
    apt-get install -y fail2ban
  elif [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
    (dnf install -y fail2ban || yum install -y fail2ban)
  fi
  # minimal jail
  mkdir -p /etc/fail2ban
  if [[ ! -f /etc/fail2ban/jail.local ]]; then
    cat >/etc/fail2ban/jail.local <<JAIL
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
JAIL
  fi
  systemctl enable fail2ban
  systemctl restart fail2ban
  sed -ri "s|(fail2ban:\n\s*enable:).*|\1 true|g" config.yaml
  sed -ri "s|(jail:).*|\1 "${FAIL2BAN_JAIL}"|g" config.yaml
else
  sed -ri "s|(fail2ban:\n\s*enable:).*|\1 false|g" config.yaml
fi
# Cloudflare
if [[ "${CF_ENABLED,,}" == "y" ]]; then
  sed -ri "s|(cloudflare:\n\s*enable:).*|\1 true|g" config.yaml
  sed -ri "s|(api_token:).*|\1 "${CF_API_TOKEN}"|g" config.yaml
  sed -ri "s|(zone_id:).*|\1 "${CF_ZONE_ID}"|g" config.yaml
else
  sed -ri "s|(cloudflare:\n\s*enable:).*|\1 false|g" config.yaml
fi

# Install service
cp "$INSTALL_DIR/vps-guardian.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "Selesai. Cek: systemctl status ${SERVICE_NAME}"

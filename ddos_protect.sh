
#!/usr/bin/env bash
set -euo pipefail
usage() {
  cat <<EOF
DDoS/SSH Hardening helper
USAGE:
  $0 apply   - Terapkan aturan yang disarankan
  $0 revert  - Hapus aturan
  $0         - Tampilkan bantuan
EOF
}
has_cmd() { command -v "$1" >/dev/null 2>&1; }
apply_ufw() {
  echo "[UFW] Limit SSH..."
  ufw limit ssh || true
  ufw reload || true
  echo "[UFW] Done."
}
revert_ufw() {
  echo "[UFW] Tidak ada revert otomatis. Gunakan 'ufw status numbered' lalu 'ufw delete <num>'."
}
apply_nft() {
  echo "[nftables] Terapkan rules dasar..."
  nft list tables | grep -q "inet filter" || nft add table inet filter
  nft list chains inet filter | grep -q "input" || nft add chain inet filter input { type filter hook input priority 0; policy accept; }
  nft add rule inet filter input tcp dport 22 ct state new limit rate over 10/minute drop || true
  echo "[nftables] Done."
}
revert_nft() {
  echo "[nftables] Hapus rule rate limit (best-effort)."
  nft -a list chain inet filter input | awk '/dport 22 ct state new limit rate over/{print $NF}' | while read -r h; do nft delete rule inet filter input handle "$h"; done || true
}
apply_iptables() {
  echo "[iptables] Terapkan limit SSH..."
  iptables -C INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH 2>/dev/null ||     iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
  iptables -C INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 --name SSH -j DROP 2>/dev/null ||     iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 --name SSH -j DROP
  echo "[iptables] Done."
}
revert_iptables() {
  iptables -D INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 --name SSH -j DROP 2>/dev/null || true
  iptables -D INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH 2>/dev/null || true
}
case "${1:-}" in
  apply)
    if has_cmd ufw; then apply_ufw
    elif has_cmd nft; then apply_nft
    else apply_iptables
    fi ;;
  revert)
    if has_cmd ufw; then revert_ufw
    elif has_cmd nft; then revert_nft
    else revert_iptables
    fi ;;
  *) usage;;
esac

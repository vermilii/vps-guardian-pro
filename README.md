
# VPS Guardian Pro — Monitoring, Anti-DDoS, Fail2ban, Cloudflare, Prometheus

**All-in-one** guardian untuk VPS kamu dengan **notifikasi Telegram**, **deteksi skrip liar (approval)**, **anti-bruteforce**, **Fail2ban** (opsional), integrasi **Cloudflare** (opsional), dan **exporter Prometheus** supaya gampang dipantau di Grafana.

## Fitur Utama
- 🔔 **Notifikasi Telegram** saat:
  - Percobaan login SSH (gagal & berhasil, dengan IP & user).
  - CPU/Mem/Disk/Load melebihi ambang.
  - Agent restart/crash, self-test, event penting lain.
- 🛡️ **Deteksi & approval eksekusi skrip mencurigakan** (pause proses, minta izin via Telegram — Allow/Block).
- 🚫 **Anti-bruteforce SSH**: auto-ban IP via nftables/iptables. (Opsional: ban juga ke **Fail2ban**).
- ☁️ **Cloudflare** (opsional): perintah Telegram untuk `/cf_blockip`, `/cf_unblockip`, dan **Under Attack Mode** on/off.
- 📈 **Prometheus exporter** di `127.0.0.1:9877/metrics` (CPU, Mem, Disk, Load, jumlah proses, jumlah IP terblokir, dll). Ready buat Grafana.
- 🔁 Kendali via Telegram:
  - `/status`, `/selftest`, `/blocked`, `/blockip`, `/unblockip`
  - `/set_chat_id`, `/set_token`, `/restart_agent`
  - `/allow <id>`, `/block <id>` (via tombol juga bisa)
  - `/whitelist add/remove user|pattern ...`
  - `/uninstall`
  - **Fail2ban**: `/f2b_status`, `/f2b_ban <ip>`, `/f2b_unban <ip>`
  - **Cloudflare**: `/cf_status`, `/cf_blockip <ip>`, `/cf_unblockip <ip>`, `/cf_underattack on|off`

> Target OS: Debian/Ubuntu (systemd).

---

## Instalasi Singkat
1) **Upload ZIP ini ke VPS** lalu:
```bash
unzip vps-guardian-pro.zip && cd vps-guardian-pro
```

2) **Install (root)** — interaktif atau non-interaktif:
```bash
# Interaktif:
sudo bash install.sh

# Non-interaktif (contoh):
sudo TELEGRAM_BOT_TOKEN="123:ABC" TELEGRAM_CHAT_ID="123456789" \
     INSTALL_FAIL2BAN="y" FAIL2BAN_JAIL="sshd" \
     CF_ENABLED="n" CF_API_TOKEN="" CF_ZONE_ID="" \
     PROM_ENABLE="y" PROM_PORT="9877" \
     bash install.sh
```

3) **Cek layanan**:
```bash
systemctl status vps-guardian
journalctl -u vps-guardian -f
```

4) **Tes Telegram**: kirim `/selftest` & `/status` ke bot kamu (pastikan sudah klik *Start*).

---

## Integrasi (Opsional)

### Fail2ban
- Installer bisa otomatis memasang dan mengaktifkan Fail2ban (jail `sshd` + recidive basic).
- Perintah bot: `/f2b_status`, `/f2b_ban <ip>`, `/f2b_unban <ip>`.

### Cloudflare
- Siapkan **API Token** dengan izin Firewall Write & Zone Read.
- Simpan `CF_API_TOKEN` dan `CF_ZONE_ID` saat instalasi (atau edit `config.yaml`).
- Perintah: `/cf_status`, `/cf_blockip <ip>`, `/cf_unblockip <ip>`, `/cf_underattack on|off`.

### Prometheus / Grafana
- Exporter on by default di `127.0.0.1:9877/metrics`.
- Tambahkan job di Prometheus scrape config (contoh di bawah).

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'vps-guardian'
    static_configs:
      - targets: ['127.0.0.1:9877']
```

---

## Struktur Proyek
```
vps-guardian-pro/
├─ install.sh
├─ uninstall.sh
├─ ddos_protect.sh
├─ vps-guardian.service
├─ vps_guardian.py
├─ config.yaml
├─ requirements.txt
├─ utils/
│  ├─ firewall.py
│  ├─ telegram_bot.py
│  ├─ monitors.py
│  ├─ fail2ban.py
│  └─ cloudflare.py
├─ README.md
└─ LICENSE
```

---

## Uninstall
Dari Telegram jalankan `/uninstall` dan konfirmasi, atau di server:
```bash
sudo bash /opt/vps-guardian/uninstall.sh
```

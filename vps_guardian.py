
#!/usr/bin/env python3
import os, sys, time, json, yaml, psutil, signal, subprocess
from typing import Dict, Any
from prometheus_client import start_http_server, Gauge
from utils.telegram_bot import TelegramBot
from utils.monitors import StateStore, ResourceMonitor, SSHMonitor, ProcessGuard, now_ts
from utils.firewall import block_ip, unblock_ip
from utils.fail2ban import available as f2b_available, banip as f2b_ban, unbanip as f2b_unban, status as f2b_status
from utils.cloudflare import CloudflareClient

CFG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

def load_cfg() -> Dict[str, Any]:
    with open(CFG_PATH, "r") as f:
        return yaml.safe_load(f)

def write_cfg(cfg: Dict[str, Any]):
    with open(CFG_PATH, "w") as f:
        yaml.safe_dump(cfg, f)

def main():
    cfg = load_cfg()
    state_path = cfg.get("state", {}).get("file", "/opt/vps-guardian/state.json")
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    st = StateStore(state_path)

    # Prometheus
    prom = cfg.get("prometheus", {})
    prom_enable = bool(prom.get("enable", False))
    prom_port = int(prom.get("port", 9877))
    if prom_enable:
        try:
            start_http_server(prom_port, addr=prom.get("bind", "127.0.0.1"))
        except Exception:
            pass
    g_cpu = Gauge("guardian_cpu_percent", "CPU percent")
    g_mem = Gauge("guardian_mem_percent", "Memory percent")
    g_disk = Gauge("guardian_disk_percent", "Disk root percent")
    g_load = Gauge("guardian_load_per_core", "1m load avg per core")
    g_proc = Gauge("guardian_processes", "Process count")
    g_blocked = Gauge("guardian_blocked_ips", "Number of blocked IPs")

    # Telegram bot
    bot = TelegramBot(cfg["telegram"]["bot_token"], cfg["telegram"]["chat_id"], cfg["telegram"]["polling_interval"])

    # Cloudflare client
    cf_cfg = cfg.get("cloudflare", {})
    cf_enabled = bool(cf_cfg.get("enable", False))
    cf = CloudflareClient(cf_cfg.get("api_token", ""), cf_cfg.get("zone_id", "")) if cf_enabled else None

    def notify(msg: str):
        bot.send_message(f"<b>[VPS Guardian]</b> {msg}")

    def approval_request(appr_id: str, user: str, cmd: str, paused: bool):
        buttons = (("✅ Allow", f"appr:allow:{appr_id}"), ("⛔ Block", f"appr:block:{appr_id}"))
        status = "PAUSED" if paused else "RUNNING"
        bot.send_message(
            f"🚧 <b>Deteksi eksekusi mencurigakan</b>\\n"
            f"ID: <code>{appr_id}</code>\\n"
            f"User: <code>{user}</code>\\n"
            f"Cmd: <code>{cmd}</code>\\n"
            f"Status: {status}\\n\\nPilih tindakan:",
            buttons=buttons
        )

    # Commands
    def cmd_status(arg):
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        loadavg = (os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0) / (os.cpu_count() or 1)
        pcount = len(psutil.pids())
        g_cpu.set(cpu); g_mem.set(mem); g_disk.set(disk); g_load.set(loadavg); g_proc.set(pcount)
        g_blocked.set(len(st.state.get("blocked_ips", {})))
        bot.send_message(f"📊 CPU {cpu:.1f}% | MEM {mem:.1f}% | DISK {disk:.1f}% | LOAD/core {loadavg:.2f} | PROC {pcount}")

    def cmd_selftest(arg):
        bot.send_message("✅ Self-test OK. Notifikasi sampai.")

    def cmd_blocked(arg):
        now = now_ts()
        items = [f"{ip} (until {exp})" for ip, exp in st.state.get("blocked_ips", {}).items() if exp > now]
        text = "Tidak ada." if not items else "\\n".join(items)
        bot.send_message("🚫 Blocked IPs:\\n" + text)

    def cmd_blockip(arg):
        ip = (arg or "").strip()
        if not ip:
            bot.send_message("Gunakan: /blockip <ip>"); return
        ok = block_ip(ip)
        if ok and cf: cf.block_ip(ip, cfg.get("cloudflare", {}).get("default_block_notes", "VPS Guardian block"))
        if ok and f2b_available() and cfg.get("fail2ban", {}).get("enable", False):
            f2b_ban(cfg["fail2ban"]["jail"], ip)
        if ok:
            st.state.setdefault("blocked_ips", {})[ip] = now_ts() + 3600
            st.save(); bot.send_message(f"🚫 {ip} diblokir (local{', CF' if cf else ''}).")
        else:
            bot.send_message(f"Gagal memblokir {ip}.")

    def cmd_unblockip(arg):
        ip = (arg or "").strip()
        if not ip: bot.send_message("Gunakan: /unblockip <ip>"); return
        ok = unblock_ip(ip)
        if cf: cf.unblock_ip(ip)
        if f2b_available() and cfg.get("fail2ban", {}).get("enable", False):
            f2b_unban(cfg["fail2ban"]["jail"], ip)
        if ok:
            st.state.get("blocked_ips", {}).pop(ip, None)
            st.save(); bot.send_message(f"♻️ {ip} dibuka blokirnya.")
        else:
            bot.send_message(f"Gagal membuka {ip}.")

    def cmd_set_chat_id(arg):
        new_id = (arg or "").strip()
        if not new_id: bot.send_message("Gunakan: /set_chat_id <id>"); return
        cfg["telegram"]["chat_id"] = new_id; write_cfg(cfg)
        bot.send_message(f"Chat ID diubah ke {new_id}.")

    def cmd_set_token(arg):
        new_tok = (arg or "").strip()
        if not new_tok: bot.send_message("Gunakan: /set_token <token>"); return
        cfg["telegram"]["bot_token"] = new_tok; write_cfg(cfg)
        bot.send_message("Token diubah. (Perlu restart agent)")

    def cmd_restart_agent(arg):
        bot.send_message("🔄 Restarting agent...")
        subprocess.Popen(["systemctl", "restart", "vps-guardian"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def cmd_uninstall(arg):
        code = str(now_ts())[-6:]
        st.state["uninstall_code"] = code; st.save()
        bot.send_message(f"⚠️ Konfirmasi uninstall dengan membalas: /uninstall {code}")
        def real_uninstall(a):
            if a.strip() == code:
                bot.send_message("🧹 Menjalankan uninstaller...")
                subprocess.Popen(["/opt/vps-guardian/uninstall.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                bot.send_message("Kode salah.")
        bot.handlers["/uninstall"] = real_uninstall

    def cmd_whitelist(arg):
        parts = (arg or "").split()
        if len(parts) < 3 or parts[0] not in ("add", "remove") or parts[1] not in ("user", "pattern"):
            bot.send_message("Gunakan: /whitelist add|remove user|pattern <value>"); return
        action, typ, value = parts[0], parts[1], " ".join(parts[2:])
        if typ == "user":
            cur = set(cfg["security"].get("whitelist_users", []))
            if action == "add": cur.add(value)
            else: cur.discard(value)
            cfg["security"]["whitelist_users"] = sorted(list(cur)); write_cfg(cfg)
            bot.send_message(f"Whitelist user -> {action} {value}")
        else:
            cur = set(cfg["security"].get("whitelist_patterns", []))
            if action == "add": cur.add(value)
            else: cur.discard(value)
            cfg["security"]["whitelist_patterns"] = sorted(list(cur)); write_cfg(cfg)
            bot.send_message(f"Whitelist pattern -> {action} {value}")

    # Fail2ban commands
    def cmd_f2b_status(arg):
        jail = cfg.get("fail2ban", {}).get("jail", "sshd")
        bot.send_message(f"<b>Fail2ban:</b>\\n{f2b_status(jail)}")
    def cmd_f2b_ban(arg):
        ip = (arg or "").strip()
        if not ip: bot.send_message("Gunakan: /f2b_ban <ip>"); return
        jail = cfg.get("fail2ban", {}).get("jail", "sshd")
        if f2b_ban(jail, ip): bot.send_message(f"Fail2ban: {ip} diban di jail {jail}.")
        else: bot.send_message("Fail2ban gagal ban IP (terpasang & jail benar?).")
    def cmd_f2b_unban(arg):
        ip = (arg or "").strip()
        if not ip: bot.send_message("Gunakan: /f2b_unban <ip>"); return
        jail = cfg.get("fail2ban", {}).get("jail", "sshd")
        if f2b_unban(jail, ip): bot.send_message(f"Fail2ban: {ip} di-unban dari jail {jail}.")
        else: bot.send_message("Fail2ban gagal unban IP.")

    # Cloudflare commands
    def cmd_cf_status(arg):
        if not cf: bot.send_message("Cloudflare tidak diaktifkan."); return
        bot.send_message(cf.status())
    def cmd_cf_blockip(arg):
        if not cf: bot.send_message("Cloudflare tidak diaktifkan."); return
        ip = (arg or "").strip()
        if not ip: bot.send_message("Gunakan: /cf_blockip <ip>"); return
        if cf.block_ip(ip, cfg.get("cloudflare", {}).get("default_block_notes", "VPS Guardian block")):
            bot.send_message(f"Cloudflare: {ip} diblokir.")
        else:
            bot.send_message("Cloudflare gagal blokir IP.")
    def cmd_cf_unblockip(arg):
        if not cf: bot.send_message("Cloudflare tidak diaktifkan."); return
        ip = (arg or "").strip()
        if not ip: bot.send_message("Gunakan: /cf_unblockip <ip>"); return
        if cf.unblock_ip(ip):
            bot.send_message(f"Cloudflare: {ip} dibuka.")
        else:
            bot.send_message("Cloudflare gagal membuka blokir IP.")
    def cmd_cf_underattack(arg):
        if not cf: bot.send_message("Cloudflare tidak diaktifkan."); return
        val = (arg or "").strip().lower()
        if val not in ("on", "off"): bot.send_message("Gunakan: /cf_underattack on|off"); return
        ok = cf.under_attack(val == "on")
        bot.send_message(f"Cloudflare Under Attack -> {val} : {'OK' if ok else 'GAGAL'}")

    # Register commands
    bot.on_command("/status", cmd_status)
    bot.on_command("/selftest", cmd_selftest)
    bot.on_command("/blocked", cmd_blocked)
    bot.on_command("/blockip", cmd_blockip)
    bot.on_command("/unblockip", cmd_unblockip)
    bot.on_command("/set_chat_id", cmd_set_chat_id)
    bot.on_command("/set_token", cmd_set_token)
    bot.on_command("/restart_agent", cmd_restart_agent)
    bot.on_command("/uninstall", cmd_uninstall)
    bot.on_command("/whitelist", cmd_whitelist)

    bot.on_command("/f2b_status", cmd_f2b_status)
    bot.on_command("/f2b_ban", cmd_f2b_ban)
    bot.on_command("/f2b_unban", cmd_f2b_unban)

    bot.on_command("/cf_status", cmd_cf_status)
    bot.on_command("/cf_blockip", cmd_cf_blockip)
    bot.on_command("/cf_unblockip", cmd_cf_unblockip)
    bot.on_command("/cf_underattack", cmd_cf_underattack)

    # Approval callbacks
    def on_approval(cb_id, payload):
        data = payload["data"]  # appr:<allow|block>:<id>
        _, decision, appr_id = data.split(":", 2)
        st.state["approvals"].setdefault(appr_id, {})["status"] = "allow" if decision == "allow" else "block"
        st.save()
        bot.answer_callback(cb_id, f"{decision.upper()} submitted")
    bot.on_callback("appr:", on_approval)

    bot.start_polling()
    notify("Service dimulai.")

    # Start monitors
    ResourceMonitor(cfg, notify).start()
    SSHMonitor(cfg, st, notify).start()
    ProcessGuard(cfg, st, notify, approval_request).start()

    # Maintenance loop
    while True:
        try:
            now = now_ts()
            expired = [ip for ip, exp in st.state.get("blocked_ips", {}).items() if exp <= now]
            for ip in expired:
                unblock_ip(ip)
                if cf: cf.unblock_ip(ip)
                if f2b_available() and cfg.get("fail2ban", {}).get("enable", False):
                    f2b_unban(cfg["fail2ban"]["jail"], ip)
                st.state["blocked_ips"].pop(ip, None)
                notify(f"♻️ IP {ip} dibuka (ban selesai).")
            st.save()
            time.sleep(30)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(5)

if __name__ == "__main__":
    main()

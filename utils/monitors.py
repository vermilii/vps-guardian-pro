
import os, time, re, json, psutil, threading, subprocess, signal
from typing import Dict, Any
from .firewall import block_ip as fw_block, unblock_ip as fw_unblock
from .fail2ban import available as f2b_available, banip as f2b_ban, unbanip as f2b_unban

def now_ts():
    return int(time.time())

class StateStore:
    def __init__(self, path: str):
        self.path = path
        self.state = {"blocked_ips": {}, "ssh_failures": {}, "approvals": {}}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as f:
                    self.state = json.load(f)
        except Exception:
            pass

    def save(self):
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, "w") as f:
                json.dump(self.state, f, indent=2)
            os.replace(tmp, self.path)
        except Exception:
            pass

class ResourceMonitor(threading.Thread):
    def __init__(self, cfg: Dict[str, Any], notifier):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.notifier = notifier
        self.cooldowns = {}

    def run(self):
        interval = self.cfg["monitoring"]["interval"]
        th_cpu = self.cfg["monitoring"]["cpu_threshold"]
        th_mem = self.cfg["monitoring"]["mem_threshold"]
        th_disk = self.cfg["monitoring"]["disk_threshold"]
        th_load = self.cfg["monitoring"]["load_threshold"]
        cooldown = self.cfg["monitoring"]["notify_cooldown_seconds"]
        nproc = os.cpu_count() or 1
        while True:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage("/").percent
                lavg = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
                lavg_per_core = lavg / nproc

                def maybe_notify(key, msg):
                    last = self.cooldowns.get(key, 0)
                    if now_ts() - last >= cooldown:
                        self.cooldowns[key] = now_ts()
                        self.notifier(msg)

                if cpu >= th_cpu: maybe_notify("cpu", f"⚠️ CPU tinggi {cpu:.1f}% (≥ {th_cpu}%)")
                if mem >= th_mem: maybe_notify("mem", f"⚠️ Memori tinggi {mem:.1f}% (≥ {th_mem}%)")
                if disk >= th_disk: maybe_notify("disk", f"⚠️ Disk penuh {disk:.1f}% (≥ {th_disk}%)")
                if lavg_per_core >= th_load: maybe_notify("load", f"⚠️ Load tinggi {lavg_per_core:.2f}/core (≥ {th_load:.2f})")

                time.sleep(interval)
            except Exception:
                time.sleep(interval)

class SSHMonitor(threading.Thread):
    FAIL_PAT = re.compile(r"(Failed password|Invalid user).+ from ([0-9.]+)")
    OK_PAT = re.compile(r"Accepted (?:password|publickey).+ from ([0-9.]+)")
    def __init__(self, cfg: Dict[str, Any], state: StateStore, notifier):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.state = state
        self.notifier = notifier

    def run(self):
        try:
            proc = subprocess.Popen(["journalctl", "-f", "-n", "0", "-u", "ssh", "-o", "cat"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except Exception:
            log = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
            proc = subprocess.Popen(["tail", "-F", log], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        th = int(self.cfg["security"]["ssh_fail_threshold"])
        ban_minutes = int(self.cfg["security"]["ssh_ban_minutes"])
        jail = self.cfg.get("fail2ban", {}).get("jail", "sshd")
        use_f2b = bool(self.cfg.get("fail2ban", {}).get("enable", False))
        window = 60
        while True:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.5); continue
            try:
                m = self.FAIL_PAT.search(line) or self.OK_PAT.search(line)
                if not m: continue
                ip = m.group(1)
                if "Failed" in line or "Invalid user" in line:
                    bucket = self.state.state["ssh_failures"].get(ip, [])
                    now = now_ts()
                    bucket = [t for t in bucket if now - t < window] + [now]
                    self.state.state["ssh_failures"][ip] = bucket
                    self.state.save()
                    if len(bucket) >= th:
                        ok = False
                        if use_f2b and f2b_available():
                            ok = f2b_ban(jail, ip)
                        if not ok:
                            ok = fw_block(ip)
                        if ok:
                            self.state.state["blocked_ips"][ip] = now + ban_minutes * 60
                            self.state.save()
                            self.notifier(f"🚫 IP {ip} diblokir {ban_minutes} menit (SSH bruteforce).")
                else:
                    self.notifier(f"✅ Login SSH berhasil dari {ip}")
            except Exception:
                pass

class ProcessGuard(threading.Thread):
    SUSP_DEFAULT = 120
    def __init__(self, cfg: Dict[str, Any], state: StateStore, notifier, approval_request):
        super().__init__(daemon=True)
        import re as _re
        self.cfg = cfg; self.state = state; self.notifier = notifier; self.approval_request = approval_request
        self.re_suspicious = [_re.compile(p, _re.I) for p in cfg["security"]["suspicious_patterns"]]
        self.watch_paths = cfg["security"]["watch_exec_paths"]
        self.whitelist_users = set(cfg["security"]["whitelist_users"] or [])
        self.whitelist_patterns = [_re.compile(p) for p in (cfg["security"]["whitelist_patterns"] or [])]
        self.seen = set()

    def is_suspicious(self, p: psutil.Process) -> bool:
        try:
            if p.username() in self.whitelist_users: return False
            exe = p.exe() if p.exe() else ""
            cmd = " ".join(p.cmdline())
            for w in self.whitelist_patterns:
                if w.search(cmd): return False
            if any((exe.startswith(w) or " /tmp" in cmd or " /var/tmp" in cmd or " /dev/shm" in cmd) for w in self.watch_paths):
                return True
            for r in self.re_suspicious:
                if r.search(cmd): return True
        except Exception:
            pass
        return False

    def run(self):
        while True:
            try:
                for p in psutil.process_iter(attrs=["pid", "ppid", "username", "cmdline"]):
                    pid = p.info["pid"]
                    if pid in self.seen or pid == os.getpid(): continue
                    self.seen.add(pid)
                    if self.is_suspicious(p): self.handle_suspicious(p)
                time.sleep(2)
            except Exception:
                time.sleep(2)

    def handle_suspicious(self, p: psutil.Process):
        try:
            pid = p.pid; user = p.username(); cmd = " ".join(p.cmdline())
            paused = False
            try:
                os.kill(pid, signal.SIGSTOP); paused = True
            except Exception: pass
            appr_id = f"{pid}-{now_ts()}"
            self.state.state["approvals"][appr_id] = {"pid": pid, "cmd": cmd, "user": user, "ts": now_ts(), "status": "pending"}
            self.state.save()
            self.approval_request(appr_id, user, cmd, paused)
            waited = 0
            while waited < self.SUSP_DEFAULT:
                st = self.state.state["approvals"].get(appr_id, {})
                if st.get("status") in ("allow", "block"): break
                time.sleep(2); waited += 2
            st = self.state.state["approvals"].get(appr_id, {})
            decision = st.get("status", "block")
            if decision == "allow":
                if paused:
                    try: os.kill(pid, signal.SIGCONT)
                    except Exception: pass
            else:
                try: os.kill(pid, signal.SIGKILL)
                except Exception: pass
        except Exception:
            pass

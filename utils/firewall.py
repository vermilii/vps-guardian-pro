
import subprocess, shutil, re

def run(cmd):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return e

def which(cmd):
    return shutil.which(cmd) is not None

def valid_ip(ip: str) -> bool:
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip))

def block_ip(ip: str) -> bool:
    if not valid_ip(ip): return False
    if which("nft"):
        run(["nft", "add", "table", "inet", "guardian"])
        run(["nft", "add", "chain", "inet", "guardian", "input",
             "{", "type", "filter", "hook", "input", "priority", "0;", "policy", "accept;", "}"])
        res = run(["nft", "add", "rule", "inet", "guardian", "input", "ip", "saddr", ip, "drop"])
        return res.returncode == 0
    elif which("iptables"):
        res = run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        return res.returncode == 0
    return False

def unblock_ip(ip: str) -> bool:
    if not valid_ip(ip): return False
    if which("nft"):
        try:
            listing = run(["nft", "-a", "list", "chain", "inet", "guardian", "input"])
            if listing.returncode == 0:
                for line in listing.stdout.splitlines():
                    if ip in line and " drop" in line and "handle" in line:
                        handle = line.strip().split()[-1]
                        run(["nft", "delete", "rule", "inet", "guardian", "input", "handle", handle])
                        return True
        except Exception:
            pass
    elif which("iptables"):
        res = run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        return res.returncode == 0
    return False

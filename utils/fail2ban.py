
import subprocess, shutil

def available() -> bool:
    return shutil.which("fail2ban-client") is not None

def run(cmd):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return e

def status(jail: str) -> str:
    if not available():
        return "Fail2ban tidak terpasang."
    res = run(["fail2ban-client", "status", jail])
    if res.returncode == 0:
        return res.stdout.strip()
    return res.stderr.strip()

def banip(jail: str, ip: str) -> bool:
    if not available(): return False
    res = run(["fail2ban-client", "set", jail, "banip", ip])
    return res.returncode == 0

def unbanip(jail: str, ip: str) -> bool:
    if not available(): return False
    res = run(["fail2ban-client", "set", jail, "unbanip", ip])
    return res.returncode == 0

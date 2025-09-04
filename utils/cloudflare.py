
import requests

class CloudflareClient:
    def __init__(self, api_token: str, zone_id: str):
        self.api_token = api_token
        self.zone_id = zone_id
        self.base = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    def _get(self, path, params=None):
        return requests.get(self.base + path, headers=self.headers, params=params, timeout=15)

    def _post(self, path, json=None):
        return requests.post(self.base + path, headers=self.headers, json=json, timeout=15)

    def _delete(self, path):
        return requests.delete(self.base + path, headers=self.headers, timeout=15)

    def _patch(self, path, json=None):
        return requests.patch(self.base + path, headers=self.headers, json=json, timeout=15)

    def status(self) -> str:
        try:
            r = self._get("/settings/under_attack_mode")
            if r.ok:
                val = r.json().get("result", {}).get("value", "unknown")
                return f"Under Attack Mode: {val}"
            return f"Cloudflare status error: {r.text[:160]}"
        except Exception as e:
            return f"Cloudflare status exception: {e}"

    def block_ip(self, ip: str, notes: str = "VPS Guardian block") -> bool:
        try:
            payload = {"mode": "block", "configuration": {"target": "ip", "value": ip}, "notes": notes}
            r = self._post("/firewall/access_rules/rules", json=payload)
            return r.ok
        except Exception:
            return False

    def find_rule_id(self, ip: str) -> str:
        try:
            params = {"configuration.target": "ip", "configuration.value": ip}
            r = self._get("/firewall/access_rules/rules", params=params)
            if r.ok:
                result = r.json().get("result", [])
                for item in result:
                    if item.get("configuration", {}).get("value") == ip:
                        return item.get("id", "")
        except Exception:
            pass
        return ""

    def unblock_ip(self, ip: str) -> bool:
        try:
            rid = self.find_rule_id(ip)
            if not rid: return False
            r = self._delete(f"/firewall/access_rules/rules/{rid}")
            return r.ok
        except Exception:
            return False

    def under_attack(self, on: bool) -> bool:
        try:
            val = "on" if on else "off"
            r = self._patch("/settings/under_attack_mode", json={"value": val})
            return r.ok
        except Exception:
            return False

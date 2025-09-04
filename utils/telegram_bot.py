
import time, threading, requests, json
from typing import Callable, Dict, Any, Optional, Tuple

class TelegramBot:
    def __init__(self, token: str, chat_id: str, poll_interval: int = 2):
        self.token = token
        self.chat_id = str(chat_id)
        self.poll_interval = int(poll_interval)
        self.base = f"https://api.telegram.org/bot{self.token}"
        self.offset = None
        self.handlers = {}
        self.cb_handlers = {}
        self.running = False
        self.thread = None

    def send_message(self, text: str, buttons: Optional[Tuple[Tuple[str, str], ...]] = None):
        data: Dict[str, Any] = {"chat_id": self.chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
        if buttons:
            keyboard = [[{"text": label, "callback_data": data} for (label, data) in buttons]]
            data["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
        try:
            requests.post(f"{self.base}/sendMessage", data=data, timeout=10)
        except Exception:
            pass

    def answer_callback(self, callback_query_id: str, text: str = "OK"):
        try:
            requests.post(f"{self.base}/answerCallbackQuery", data={"callback_query_id": callback_query_id, "text": text}, timeout=10)
        except Exception:
            pass

    def on_command(self, cmd: str, fn: Callable[[str], None]):
        self.handlers[cmd] = fn

    def on_callback(self, key: str, fn: Callable[[str, Dict[str, Any]], None]):
        self.cb_handlers[key] = fn

    def start_polling(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()

    def stop(self): self.running = False

    def _poll_loop(self):
        while self.running:
            try:
                params = {"timeout": 30}
                if self.offset is not None:
                    params["offset"] = self.offset
                resp = requests.get(f"{self.base}/getUpdates", params=params, timeout=35)
                data = resp.json()
                for upd in data.get("result", []):
                    self.offset = upd["update_id"] + 1
                    if "message" in upd and "text" in upd["message"]:
                        msg = upd["message"]["text"].strip()
                        cid = str(upd["message"]["chat"]["id"])
                        if cid != self.chat_id:  # accept only configured chat
                            continue
                        parts = msg.split()
                        cmd = parts[0].lower()
                        arg = " ".join(parts[1:]) if len(parts) > 1 else ""
                        if cmd in self.handlers:
                            try: self.handlers[cmd](arg)
                            except Exception: pass
                    if "callback_query" in upd:
                        cq = upd["callback_query"]
                        cid = str(cq["message"]["chat"]["id"])
                        if cid != self.chat_id: continue
                        data = cq.get("data", "")
                        for key, fn in self.cb_handlers.items():
                            if data.startswith(key):
                                try: fn(cq["id"], {"data": data, "message": cq.get("message", {})})
                                except Exception: pass
                                break
            except Exception:
                time.sleep(self.poll_interval)
            time.sleep(self.poll_interval)

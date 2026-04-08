#!/usr/bin/python3
import os
import sys
import json
import re
import io
import requests
import urllib3

from dotenv import load_dotenv
from pathlib import Path
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from PIL import Image

env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

# ===========================================
EXPRESS_URL = os.getenv("EXPRESS_URL")
EXPRESS_TOKEN = os.getenv("EXPRESS_TOKEN")
ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_USER = os.getenv("ZABBIX_USER")
ZABBIX_PASSWORD = os.getenv("ZABBIX_PASSWORD")
GRAPH_WIDTH = int(os.getenv("GRAPH_WIDTH", "900"))
GRAPH_HEIGHT = int(os.getenv("GRAPH_HEIGHT", "200"))
CACHE_FILE = os.getenv("CACHE_FILE")
LOG_FILE = os.getenv("LOG_FILE")
# ===========================================

# Убираем ошибки самоподписа
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} - {msg}\n")
    except Exception:
        pass


# Скипаем мусор заббикса
def is_unresolved_macro(value) -> bool:
    value = str(value).strip() if value else ""
    if not value:
        return True

    upper_value = value.upper()

    return (
        (value.startswith("{") and value.endswith("}")) or
        upper_value in {"UNKNOWN", "*UNKNOWN*", "UNDEFINED", "*UNDEFINED*", "NONE", "NULL", "-"}
    )


def build_event_url(trigger_id: str, event_id: str) -> str:
    if is_unresolved_macro(trigger_id) or is_unresolved_macro(event_id) or not ZABBIX_URL:
        return ""
    return f"{ZABBIX_URL.rstrip('/')}/tr_events.php?triggerid={trigger_id}&eventid={event_id}"


def parse_zabbix_payload(raw: str) -> dict:
    # Иногда может прлететь в payload невалидный хлам, если кривой, пытаемся его распарсить:
    raw = (raw or "").strip()

    try:
        return json.loads(raw)
    except Exception as e:
        log(f"Standard JSON parse failed: {e}")

    keys = [
        "event_id",
        "trigger_id",
        "event_name",
        "host_name",
        "severity",
        "event_value",
        "event_update_status",
        "last_value",
        "event_time",
        "event_date",
        "duration",
        "event_tags",
        "trigger_url",
        "item_id1",
        "item_id2",
        "item_id3",
        "item_id4",
        "host_id",
        "action_id",
        "send_to",
    ]

    result = {}

    try:
        for i, key in enumerate(keys):
            pattern = rf'"{re.escape(key)}"\s*:\s*"'
            m = re.search(pattern, raw, flags=re.DOTALL)
            if not m:
                continue

            start = m.end()
            next_pos = len(raw)

            for next_key in keys[i + 1:]:
                nm = re.search(
                    rf'"\s*,\s*"{re.escape(next_key)}"\s*:\s*"',
                    raw[start:],
                    flags=re.DOTALL
                )
                if nm:
                    next_pos = start + nm.start()
                    break

            value = raw[start:next_pos]

            if value.endswith('",'):
                value = value[:-2]
            elif value.endswith('"'):
                value = value[:-1]

            value = value.replace("\r\n", "\n").replace("\r", "\n")
            result[key] = value.strip()

        if not result:
            raise ValueError("Fallback parser extracted 0 fields")

        log(f"Fallback parser used successfully. Keys: {list(result.keys())}")
        return result

    except Exception as e:
        log(f"Fallback parse failed: {e}")
        raise

@dataclass
class AlertData:
    event_id: str
    trigger_id: str
    event_name: str
    host_name: str
    severity: str
    event_value: str
    event_update_status: str
    last_value: str
    event_time: str
    event_date: str
    duration: str
    event_tags: str
    trigger_url: str
    item_id1: str
    item_id2: str = ""
    item_id3: str = ""
    item_id4: str = ""
    host_id: str = ""
    action_id: str = ""

class SyncCache:
    def __init__(self, path):
        self.path = path

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self, data):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as e:
            log(f"Cache save error: {e}")

    def get(self, chat_id, event_id):
        return self._load().get(f"{chat_id}:{event_id}")

    def set(self, chat_id, event_id, sync_id):
        data = self._load()
        data[f"{chat_id}:{event_id}"] = sync_id
        self._save(data)

class MessageBuilder:
    @staticmethod
    def _status_emoji(last_value: str) -> str:
        v = (last_value or "").lower()

        if "success" in v or "ok" in v or "up" in v or "running" in v:
            return "💚"
        if "active" in v:
            return "💚"
        if "deactivating" in v or "stopping" in v:
            return "🧡"
        if "failed" in v or "error" in v or "down" in v or "inactive" in v:
            return "💔"
        if "starting" in v or "reload" in v or "reloading" in v:
            return "🔄"
        return "⚪"

    @staticmethod
    def _sanitize_tag_part(value: str) -> str:
        value = str(value or "").strip().lower()

        # убираем мусорные хвосты от json/shell/zabbix
        value = value.replace("\r", "").replace("\n", "").replace("\t", "")
        value = value.replace('"', "").replace("'", "")
        value = value.replace("{", "").replace("}", "")

        value = (
            value.replace(" ", "_")
                 .replace(".", "_")
                 .replace("-", "_")
                 .replace("/", "_")
                 .replace(":", "_")
                 .replace("[", "")
                 .replace("]", "")
                 .replace("(", "")
                 .replace(")", "")
                 .replace(",", "")
                 .replace(";", "")
        )

        value = re.sub(r"[^a-zа-яё0-9_]+", "", value, flags=re.IGNORECASE)

        while "__" in value:
            value = value.replace("__", "_")

        return value.strip("_")

    def _format_tags(self, a: AlertData) -> str:
        tags = []
        seen = set()

        def add_tag(tag: str):
            if not tag:
                return
            if tag not in seen:
                seen.add(tag)
                tags.append(tag)

        if not is_unresolved_macro(a.event_tags):
            raw_tags = a.event_tags

            pairs = re.findall(r'\[([^\[\]:]+)\s*:\s*([^\[\]]+)\]', raw_tags)

            if pairs:
                for key, value in pairs:
                    key = self._sanitize_tag_part(key)
                    value = self._sanitize_tag_part(value)

                    if not key or not value:
                        continue
                    if "zbx_ex_sync_id" in key:
                        continue

                    add_tag(f"#{key}_{value}")
            else:
                for raw in raw_tags.split(","):
                    raw = raw.strip()
                    if not raw:
                        continue

                    if ":" in raw:
                        key, value = raw.split(":", 1)
                        key = self._sanitize_tag_part(key)
                        value = self._sanitize_tag_part(value)

                        if not key or not value:
                            continue
                        if key == "__zbx_ex_sync_id":
                            continue

                        add_tag(f"#{key}_{value}")
                    else:
                        value = self._sanitize_tag_part(raw)
                        if value:
                            add_tag(f"#{value}")

        if not is_unresolved_macro(a.event_id):
            add_tag(f"#eid_{self._sanitize_tag_part(a.event_id)}")

        if not is_unresolved_macro(a.item_id1):
            add_tag(f"#iid_{self._sanitize_tag_part(a.item_id1)}")

        if not is_unresolved_macro(a.item_id2):
            add_tag(f"#iid_{self._sanitize_tag_part(a.item_id2)}")

        if not is_unresolved_macro(a.item_id3):
            add_tag(f"#iid_{self._sanitize_tag_part(a.item_id3)}")

        if not is_unresolved_macro(a.item_id4):
            add_tag(f"#iid_{self._sanitize_tag_part(a.item_id4)}")

        if not is_unresolved_macro(a.trigger_id):
            add_tag(f"#tid_{self._sanitize_tag_part(a.trigger_id)}")

        if not is_unresolved_macro(a.action_id):
            add_tag(f"#aid_{self._sanitize_tag_part(a.action_id)}")

        if not is_unresolved_macro(a.host_id):
            add_tag(f"#hid_{self._sanitize_tag_part(a.host_id)}")

        return " ".join(tags)

    def build(self, a: AlertData) -> str:
        is_recovery = a.event_value == "0"
        icon = "✅" if is_recovery else "🚨"
        status = self._status_emoji(a.last_value)
        time_str = a.event_time[:5] if not is_unresolved_macro(a.event_time) else ""
        tags = self._format_tags(a)
        event_url = build_event_url(a.trigger_id, a.event_id)

        lines = [
            f"{icon} {a.severity} {status}: {a.event_name}",
            f"💻 Host: {a.host_name}"
        ]

        if not is_unresolved_macro(a.last_value):
            lines.append(f"⏮️ Last value: {a.last_value}" + (f" ({time_str})" if time_str else ""))

        if not is_unresolved_macro(a.duration):
            lines.append(f"🕠 Duration: {a.duration}")

        if event_url:
            lines.append(f"ℹ️ Event info: {event_url}")

        if tags:
            lines += ["", tags]

        return "\n".join(lines)

class ZabbixGraphFetcher:
    def __init__(self, url, user, password):
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.session = None

    def _login(self):
        try:
            s = requests.Session()
            s.verify = False
            r = s.post(
                f"{self.url}/index.php",
                data={
                    "name": self.user,
                    "password": self.password,
                    "autologin": "1",
                    "enter": "Sign in"
                },
                timeout=15,
                allow_redirects=True
            )

            log(f"Zabbix login final URL: {r.url}")

            if "dashboard" in r.url or "zabbix.php" in r.url:
                return s

            log(f"Login failed: {r.text[:300]}")
        except Exception as e:
            log(f"Zabbix login failed: {e}")
        return None

    def fetch(self, item_id):
        if not str(item_id).isdigit():
            log(f"Invalid item_id for graph: {item_id}")
            return None

        try:
            if not self.session:
                self.session = self._login()
                if not self.session:
                    return None

            r = self.session.get(
                f"{self.url}/chart.php",
                params={
                    "itemids[]": item_id,
                    "from": "now-2h",
                    "to": "now",
                    "width": GRAPH_WIDTH,
                    "height": GRAPH_HEIGHT
                },
                timeout=15
            )

            if "image" in r.headers.get("content-type", ""):
                log(f"Graph fetched for item {item_id}: {len(r.content)} bytes")
                return r.content

            log(f"Graph fetch failed for item {item_id}: {r.text[:300]}")
        except Exception as e:
            log(f"Graph fetch exception: {e}")
        return None

# Недорозамещение не умеет грузить пока несколько картинок. Потому объеденим все графы в одну вертикальную картинку:
def merge_images_vertical(images) -> bytes | None:
    try:
        valid_images = [img for img in images if img]
        if not valid_images:
            return None

        if len(valid_images) == 1:
            return valid_images[0]

        pil_images = []
        for img_bytes in valid_images:
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            pil_images.append(img)

        max_width = max(img.width for img in pil_images)
        total_height = sum(img.height for img in pil_images)

        merged = Image.new("RGB", (max_width, total_height), (255, 255, 255))

        y_offset = 0
        for img in pil_images:
            x_offset = (max_width - img.width) // 2 if img.width != max_width else 0
            merged.paste(img, (x_offset, y_offset))
            y_offset += img.height

        output = io.BytesIO()
        merged.save(output, format="PNG")
        result = output.getvalue()

        log(f"Merged {len(valid_images)} graphs into one image: {len(result)} bytes")
        return result

    except Exception as e:
        log(f"merge_images_vertical failed: {e}")
        return None

class ExpressMessenger:
    def __init__(self, url, token):
        self.url = url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def _post(self, endpoint, payload):
        try:
            r = requests.post(
                f"{self.url}{endpoint}",
                headers=self.headers,
                json=payload,
                timeout=15
            )

            if r.status_code in (200, 202):
                try:
                    return r.json().get("result", {})
                except Exception:
                    return {}

            log(f"HTTP {r.status_code}: {r.text[:300]}")
        except Exception as e:
            log(f"Request failed: {e}")
        return None

    def send(self, chat_id, message, image=None):
        payload = {
            "group_chat_id": chat_id,
            "notification": {"status": "ok", "body": message}
        }
        if image:
            payload["file"] = {
                "data": f"data:image/png;base64,{b64encode(image).decode()}",
                "file_name": "graph.png"
            }
        return self._post("/api/v4/botx/notifications/direct", payload)

    def reply(self, sync_id, message, image=None):
        payload = {
            "source_sync_id": sync_id,
            "reply": {"status": "ok", "body": message}
        }
        if image:
            payload["file"] = {
                "data": f"data:image/png;base64,{b64encode(image).decode()}",
                "file_name": "graph.png"
            }
        return self._post("/api/v3/botx/events/reply_event", payload)

def main():
    log("=" * 80)
    log(f"Started with argv: {sys.argv}")

    if len(sys.argv) < 3:
        log("FAILED: Not enough arguments")
        print("FAILED")
        sys.exit(1)

    send_to = sys.argv[1]
    if is_unresolved_macro(send_to):
        log("FAILED: send_to not resolved")
        print("FAILED")
        sys.exit(1)

    try:
        raw_payload = sys.argv[2]
        data = parse_zabbix_payload(raw_payload)
        data.pop("send_to", None)
        log(f"Parsed payload keys: {list(data.keys())}")
        alert = AlertData(**data)
    except Exception as e:
        log(f"Input parse error: {e}")
        print("FAILED")
        sys.exit(1)

    msg = MessageBuilder().build(alert)
    log(f"Built message:\n{msg}")

    graph = None
    fetcher = ZabbixGraphFetcher(ZABBIX_URL, ZABBIX_USER, ZABBIX_PASSWORD)

    item_ids = [
        alert.item_id1,
        alert.item_id2,
        alert.item_id3,
        alert.item_id4,
    ]

    valid_item_ids = []
    for item_id in item_ids:
        if not is_unresolved_macro(item_id) and str(item_id).isdigit():
            if item_id not in valid_item_ids:
                valid_item_ids.append(item_id)

    log(f"Valid item_ids for graph: {valid_item_ids}")

    if valid_item_ids:
        graph_list = []
        for item_id in valid_item_ids:
            img = fetcher.fetch(item_id)
            if img:
                graph_list.append(img)

        graph = merge_images_vertical(graph_list)

    messenger = ExpressMessenger(EXPRESS_URL, EXPRESS_TOKEN)
    cache = SyncCache(CACHE_FILE)

    is_problem = alert.event_value == "1" and alert.event_update_status != "1"
    log(f"is_problem={is_problem}, event_id={alert.event_id}")

    if is_problem:
        res = messenger.send(send_to, msg, graph)
        log(f"Send result: {res}")
        if res and "sync_id" in res:
            cache.set(send_to, alert.event_id, res["sync_id"])
    else:
        sync_id = cache.get(send_to, alert.event_id)
        if sync_id:
            res = messenger.reply(sync_id, msg, graph)
            log(f"Reply result: {res}")
        else:
            res = messenger.send(send_to, msg, graph)
            log(f"Fallback send result: {res}")

    print("OK")

if __name__ == "__main__":
    main()
# state.py
import os, json, time, threading
from typing import Dict, Any

_LOCK = threading.Lock()

def _ensure_dir(p: str):
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)

def load_state(path: str):
    try:
        # use utf-8-sig to auto-strip BOM if present
        with open(path, "r", encoding="utf-8-sig") as f:
            data = f.read().strip()
            if not data:
                return {"sites": {}}
            return json.loads(data)
    except FileNotFoundError:
        return {"sites": {}}
    except json.JSONDecodeError:
        return {"sites": {}}

def save_state(path: str, state: Dict[str, Any]) -> None:
    _ensure_dir(path)
    tmp = path + ".tmp"
    with _LOCK, open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def upsert_match(state: Dict[str, Any], base: str, image_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    now = payload.get("timestamp_utc") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    site = state.setdefault("sites", {}).setdefault(base, {"matches": {}})
    m = site["matches"].get(image_url)
    if m:
        m["last_seen_utc"] = now
        m["seen_count"] = int(m.get("seen_count", 1)) + 1
        for k in ("host_page","term","matched_known_file","saved_copy"):
            if payload.get(k):
                m[k] = payload[k]
    else:
        site["matches"][image_url] = {
            "status": "new",       # new | ack | closed
            "muted": False,        # if True, never alert again
            "notes": [],           # [{"ts","text"}]
            "first_seen_utc": now,
            "last_seen_utc": now,
            "seen_count": 1,
            **{k: payload.get(k) for k in ("host_page","term","matched_known_file","saved_copy")}
        }
    return site["matches"][image_url]

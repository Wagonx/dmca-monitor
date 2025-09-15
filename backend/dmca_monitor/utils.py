import os, io, json, csv, logging, requests, imagehash
from datetime import time
from typing import List, Dict, Any, Optional
from PIL import Image, UnidentifiedImageError
import numpy as np
from urllib.parse import urlparse
try:
    from skimage.metrics import structural_similarity as ssim
except Exception:
    ssim = None


def ensure_dirs(*paths):
    for p in paths:
        if p:
            os.makedirs(p, exist_ok=True)


def load_json(path: str, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def save_json(path: str, data):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def pil_open_safe(b: bytes):
    try:
        img = Image.open(io.BytesIO(b))
        img = img.convert("RGB")
        return img
    except UnidentifiedImageError:
        return None


def compute_hashes(img: Image.Image) -> Dict[str, str]:
    # multiple hashes for robustness to crops/resizes
    return {
        "phash": str(imagehash.phash(img)),
        "dhash": str(imagehash.dhash(img)),
        "ahash": str(imagehash.average_hash(img)),
        "whash": str(imagehash.whash(img))
    }


def hash_distance(h1: str, h2: str) -> int:
    return imagehash.hex_to_hash(h1) - imagehash.hex_to_hash(h2)


def any_distance_below(candidate: Dict[str, str], target: Dict[str, str], threshold: int) -> bool:
    for k in candidate.keys():
        if k in target:
            if hash_distance(candidate[k], target[k]) <= threshold:
                return True
    return False


def ssim_match(imgA: Image.Image, imgB: Image.Image, min_score: float = 0.82) -> bool:
    if ssim is None:
        return False
    size = (256, 256)
    a = np.asarray(imgA.resize(size)).astype(np.float32) / 255.0
    b = np.asarray(imgB.resize(size)).astype(np.float32) / 255.0
    score = ssim(a, b, channel_axis=2)
    return score >= min_score


def download_image(url: str, timeout: int = 15):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "DMCA-Monitor/1.0"})
        if r.status_code == 200 and r.content:
            return pil_open_safe(r.content)
        return None
    except requests.RequestException:
        return None


def log_match(csv_path: str, row: Dict[str, Any]):
    d = os.path.dirname(csv_path)
    if d:
        os.makedirs(d, exist_ok=True)
    new_file = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def slack_notify(webhook: str, text: str):
    if not webhook:
        return
    try:
        requests.post(webhook, json={"text": text}, timeout=10)
    except requests.RequestException:
        pass

def _discord_post(webhook: str, payload: dict, timeout: int = 10):
    # Discord rate-limits with 429; basic retry
    for attempt in range(3):
        try:
            r = requests.post(webhook, json=payload, timeout=timeout)
            if r.status_code == 204 or (200 <= r.status_code < 300):
                return True
            if r.status_code == 429:
                wait = (r.json().get("retry_after", 1000)) / 1000.0
                time.sleep(min(wait, 5))
                continue
            return False
        except requests.RequestException:
            time.sleep(0.5)
    return False

def discord_notify(
    webhook: str,
    text: str,
    username: str | None = None,
    avatar_url: str | None = None,
):
    """
    Sends plain text to a Discord webhook. Splits messages to respect the 2000-char limit.
    """
    if not webhook:
        return

    # Discord hard limit is 2000 characters per message.
    MAX_LEN = 2000
    chunks = [text[i:i+MAX_LEN] for i in range(0, len(text), MAX_LEN)] or ["(empty)"]

    for chunk in chunks:
        payload = {
            "content": chunk,
            "allowed_mentions": {"parse": []},  # avoid accidental pings
            "flags": 4,  # SUPPRESS_EMBEDS
        }
        if username:
            payload["username"] = username
        if avatar_url:
            payload["avatar_url"] = avatar_url
        _discord_post(webhook, payload)

def init_logger_to_logs(log_filename: str = "debug.log") -> str:
    """Initialize logging to <repo-root>/logs/<log_filename>."""
    here = os.path.dirname(os.path.abspath(__file__))          # backend/dmca_monitor
    repo_root = os.path.abspath(os.path.join(here, "..", ".."))# repo root
    log_dir = os.path.join(repo_root, "logs")
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, log_filename)
    if not logging.getLogger().handlers:
        logging.basicConfig(
            filename=path,
            filemode="a",
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
    return path

def cse_fetch_paginated(
    api_key: str,
    cse_id: str,
    query: str,
    count: int,
    *,
    search_type: Optional[str] = None,  # "image" or None
    per_page: int = 10,
    request_timeout: int = 20,
    max_start: int = 91,                # CSE caps start so 1..91 gives 10 pages
    backoff_secs: float = 1.5,
) -> List[Dict[str, Any]]:
    """
    Unified Google Programmable Search pagination.
    Returns the raw 'items' dicts across pages.
    """
    init_logger_to_logs()  # ensure logger is targeting /logs/debug.log
    items_all: List[Dict[str, Any]] = []
    remaining = max(0, int(count))
    start = 1

    while remaining > 0 and start <= max_start:
        page_count = min(per_page, remaining)
        params = {
            "key": api_key,
            "cx": cse_id,
            "q": query,
            "num": page_count,
            "start": start,
            "safe": "off",
        }
        if search_type:
            params["searchType"] = search_type

        try:
            r = requests.get("https://www.googleapis.com/customsearch/v1",
                             params=params, timeout=request_timeout)
            if r.status_code in (429, 500, 502, 503, 504):
                logging.warning("CSE %s %s rate/serve issue (status=%s). Backing off %.1fs",
                                search_type or "web", query, r.status_code, backoff_secs)
                time.sleep(backoff_secs)
                continue
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logging.exception("CSE request failed for %s (%s): %s",
                              query, search_type or "web", e)
            break

        items = data.get("items") or []
        logging.debug("CSE page %s type=%s got=%d start=%d",
                      query, search_type or "web", len(items), start)
        items_all.extend(items)

        got = len(items)
        if got == 0:
            break
        remaining -= got
        start += got

    return items_all

def normalize_saved_rel(saved_copy_path: str, downloads_folder_name: str = "scratch/downloads") -> str:
    """
    Turn absolute/OS-specific saved_copy path into a clean URL-relative path for /downloads/<path>.
    """
    if not saved_copy_path:
        return ""
    rel = os.path.normpath(saved_copy_path).replace("\\", "/")
    if f"{downloads_folder_name}/" in rel:
        rel = rel.split(f"{downloads_folder_name}/", 1)[-1]
    return rel

def canonical_base_url(u: str) -> str:
    """Consistent base-url extraction for both scanner and UI."""
    try:
        p = urlparse(u or "")
        if p.netloc:
            return p.netloc.lower()
        return (u or "").lower()
    except Exception:
        return "(unknown)"
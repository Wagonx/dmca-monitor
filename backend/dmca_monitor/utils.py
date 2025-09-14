
from typing import Dict, Any
from PIL import Image, UnidentifiedImageError
import imagehash
import numpy as np
import os, logging, requests, io, json, csv, re, time
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


def download_image(url: str, timeout: int = 15, *, referer: str | None = None):
    headers = {
        "User-Agent": "DMCA-Monitor/1.0",
    }
    if referer:
        headers["Referer"] = referer
    try:
        r = requests.get(url, timeout=timeout, headers=headers, stream=True)
        r.raise_for_status()
        im = Image.open(io.BytesIO(r.content)).convert("RGB")
        return im
    except Exception:
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

_URL_RE = re.compile(r'(?P<url>https?://\S+)')

def _suppress_links(text: str) -> str:
    # Wraps every URL in <...> so Discord won't auto-embed
    return _URL_RE.sub(lambda m: f"<{m.group('url')}>", text)

def _discord_post(webhook: str, payload: dict, *, timeout: int = 10) -> requests.Response:
    # Always send JSON, raise on error, and log useful context
    r = requests.post(webhook, json=payload, timeout=timeout)
    try:
        r.raise_for_status()
    except Exception:
        snippet = ""
        try:
            snippet = r.text[:300]
        except Exception:
            pass
        logging.error("Discord webhook error %s: %s", r.status_code, snippet)
        raise
    return r

def discord_notify(
    webhook: str,
    text: str,
    username: str | None = None,
    avatar_url: str | None = None,
    *, suppress_embeds: bool = True
):
    """
    Sends plain text to a Discord webhook. Splits messages to respect the 2000-char limit.
    Tries flags-based embed suppression; falls back to <url> wrapping if Discord rejects it.
    """
    if not webhook:
        return

    MAX_LEN = 2000
    chunks = [text[i:i+MAX_LEN] for i in range(0, len(text), MAX_LEN)] or ["(empty)"]

    for chunk in chunks:
        payload = {
            "content": chunk,
            "allowed_mentions": {"parse": []},  # avoid accidental pings
        }
        if username:
            payload["username"] = username
        if avatar_url:
            payload["avatar_url"] = avatar_url

        if suppress_embeds:
            # First attempt: flags=4 (SUPPRESS_EMBEDS)
            try:
                p = dict(payload)
                p["flags"] = 4
                _discord_post(webhook, p)
                continue  # success; next chunk
            except Exception:
                # Fallback: wrap links in <...> and send without flags
                pass

            try:
                wrapped = _suppress_links(chunk)
                p = dict(payload)
                p["content"] = wrapped
                _discord_post(webhook, p)
            except Exception:
                # Give up on this chunk; continue with others
                logging.exception("Discord notify failed even after fallback.")
        else:
            # No suppression requested
            _discord_post(webhook, payload)
# --- common helpers to dedupe loops & behavior ---

def init_logger_to_logs(log_filename: str = "debug.log") -> str:
    """Initialize logging to <repo-root>/logs/<log_filename> and return the path."""
    # Resolve repo root as backend/.. (works from both CLI and webapp contexts)
    here = os.path.dirname(os.path.abspath(__file__))          # backend/dmca_monitor
    root = os.path.abspath(os.path.join(here, ".."))           # backend
    repo_root = os.path.abspath(os.path.join(root, ".."))      # repo root
    log_dir = os.path.join(repo_root, "logs")
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, log_filename)
    logging.basicConfig(
        filename=path,
        filemode="a",
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    return path

def canonical_base_url(u: str) -> str:
    """Consistent base-url extraction for both scanner and UI."""
    try:
        p = urlparse(u or "")
        if p.netloc:
            return p.netloc.lower()
        return (u or "").lower()
    except Exception:
        return "(unknown)"

def cse_fetch_paginated(api_key: str, cse_id: str, query: str, count: int, *, search_type: str | None):
    """
    Unified Google CSE pagination for image or web.
    Returns list of raw items (dicts) as delivered by the CSE API.
    """
    import requests
    items_all = []
    remaining = max(0, int(count))
    start = 1
    while remaining > 0 and start <= 91:
        page_count = min(10, remaining)
        params = {
            "key": api_key, "cx": cse_id, "q": query,
            "num": page_count, "start": start, "safe": "off",
        }
        if search_type:
            params["searchType"] = search_type  # "image" for images
        r = requests.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        items = data.get("items") or []
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
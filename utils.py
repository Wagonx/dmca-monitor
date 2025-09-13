import os, io, json, csv
from typing import Dict, Any
import requests
from PIL import Image, UnidentifiedImageError
import imagehash
import numpy as np

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
        }
        if username:
            payload["username"] = username
        if avatar_url:
            payload["avatar_url"] = avatar_url
        _discord_post(webhook, payload)
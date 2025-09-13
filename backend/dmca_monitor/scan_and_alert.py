import argparse, os, json
import yaml
import requests
from bs4 import BeautifulSoup
from PIL import Image
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from utils import (
    ensure_dirs, load_json, save_json, compute_hashes, any_distance_below,
    download_image, log_match, ssim_match
)

# try local state.py; if you packaged under backend/dmca_monitor, the plain import still works when PYTHONPATH=backend
from state import load_state, save_state, upsert_match

# ---------- Google Programmable Search helpers ----------

def google_image_search(api_key: str, cse_id: str, query: str, count: int):
    results = []
    remaining = max(0, int(count))
    start = 1
    while remaining > 0 and start <= 91:
        page_count = min(10, remaining)
        params = {
            "key": api_key, "cx": cse_id, "q": query,
            "searchType": "image", "num": page_count, "start": start, "safe": "off",
        }
        r = requests.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        items = data.get("items") or []
        for it in items:
            link = it.get("link")
            ctx  = it.get("image", {}).get("contextLink") or it.get("link")
            if link:
                results.append((link, ctx))
        got = len(items)
        if got == 0:
            break
        remaining -= got
        start += got
    return results

def google_web_search(api_key: str, cse_id: str, query: str, count: int):
    urls = []
    remaining = max(0, int(count))
    start = 1
    while remaining > 0 and start <= 91:
        page_count = min(10, remaining)
        params = {
            "key": api_key, "cx": cse_id, "q": query,
            "num": page_count, "start": start, "safe": "off",
        }
        r = requests.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        items = data.get("items") or []
        for it in items:
            link = it.get("link")
            if link:
                urls.append(link)
        got = len(items)
        if got == 0:
            break
        remaining -= got
        start += got
    return urls

def extract_images_from_page(page_url: str, timeout: int = 15):
    try:
        r = requests.get(page_url, timeout=timeout, headers={"User-Agent": "DMCA-Monitor/1.0"})
    except requests.RequestException:
        return []
    if r.status_code != 200:
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    imgs = []
    for img in soup.find_all("img"):
        src = img.get("src") or img.get("data-src") or img.get("data-original")
        if not src:
            continue
        imgs.append(urljoin(page_url, src))
    return imgs

def base_url(u: str) -> str:
    try:
        p = urlparse(u or "")
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}".lower()
        return (p.netloc or u).lower()
    except Exception:
        return "(unknown)"

# ---------- Main scan ----------

def main(cfg_path: str):
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    terms = cfg.get("search_terms", [])
    engines = cfg.get("engines", {})
    notify = cfg.get("notify", {})
    mcfg = cfg.get("match", {})
    paths = cfg.get("paths", {})
    timeouts = cfg.get("timeouts", {})

    threshold = int(mcfg.get("threshold", 7))
    use_ssim = bool(mcfg.get("use_ssim", False))

    hash_db_path = paths.get("hash_db", "db/hashes.json")
    seen_cache_path = paths.get("seen_cache", "db/seen.json")
    alerts_state_path = paths.get("alerts_state", "db/alerts.json")  # NEW
    logs_csv = paths.get("logs_csv", "logs/matches.csv")
    downloads_dir = paths.get("downloads", "scratch/downloads")

    ensure_dirs(os.path.dirname(hash_db_path), os.path.dirname(seen_cache_path),
                os.path.dirname(alerts_state_path), os.path.dirname(logs_csv), downloads_dir)

    with open(hash_db_path, "r", encoding="utf-8") as f:
        known_hashes = json.load(f)

    seen = load_json(seen_cache_path, default={"urls": []})
    seen_urls = set(seen.get("urls", []))

    alerts = load_state(alerts_state_path)  # NEW

    # Google config
    gcfg = engines.get("google", {})
    google_enabled = bool(gcfg.get("enabled", True))
    g_api_key = gcfg.get("api_key", "")
    g_cse_id = gcfg.get("cse_id", "")
    g_img_count = int(gcfg.get("image_count_per_term", 10))
    g_web_count = int(gcfg.get("web_count_per_term", 0))

    # Discord (optional)
    discord_hook = notify.get("discord_webhook", "")
    discord_username = notify.get("discord_username", None)
    discord_avatar = notify.get("discord_avatar_url", None)
    def notify_discord(msg: str):
        try:
            from utils import discord_notify
            if discord_hook:
                discord_notify(discord_hook, msg, username=discord_username, avatar_url=discord_avatar)
        except Exception:
            pass

    now = datetime.now(timezone.utc).isoformat()
    grouped = defaultdict(list)  # base_url -> list[row] (only "new" & not muted)

    for term in terms:
        candidates = []

        if google_enabled and g_api_key and g_cse_id:
            try:
                candidates.extend(google_image_search(g_api_key, g_cse_id, term, g_img_count))
            except Exception:
                pass
            if g_web_count > 0:
                try:
                    pages = google_web_search(g_api_key, g_cse_id, term, g_web_count)
                    for p in pages:
                        for img_url in extract_images_from_page(p, timeout=int(timeouts.get("request", 15))):
                            candidates.append((img_url, p))
                except Exception:
                    pass

        for img_url, host in candidates:
            if img_url in seen_urls:
                continue
            seen_urls.add(img_url)

            img = download_image(img_url, timeout=int(timeouts.get("request", 15)))
            if img is None:
                continue

            cand_hashes = compute_hashes(img)
            matched_key = None

            for kpath, khashes in known_hashes.items():
                if any_distance_below(cand_hashes, khashes, threshold):
                    if use_ssim:
                        try:
                            with Image.open(kpath).convert("RGB") as base_img:
                                if not ssim_match(base_img, img):
                                    continue
                        except Exception:
                            pass
                    matched_key = kpath
                    break

            if matched_key:
                fname = os.path.basename(urlparse(img_url).path) or "image.jpg"
                out_path = os.path.join(downloads_dir, fname)
                try:
                    img.save(out_path)
                except Exception:
                    out_path = ""

                row = {
                    "timestamp_utc": now,
                    "term": term,
                    "image_url": img_url,
                    "host_page": host or "",
                    "matched_known_file": matched_key,
                    "saved_copy": out_path
                }

                # Always keep audit log
                log_match(logs_csv, row)

                # Update per-site alert state
                site_key = base_url(row["host_page"] or row["image_url"])
                rec = upsert_match(alerts, site_key, row["image_url"], {**row, "timestamp_utc": now})

                # Notify only if first time (status=new) and not muted
                if (rec.get("status") == "new") and (not rec.get("muted", False)):
                    grouped[site_key].append(row)

    # Persist caches/state
    save_json(seen_cache_path, {"urls": sorted(list(seen_urls))})
    save_state(alerts_state_path, alerts)

    # ---- One Discord message per base URL ----
    def format_line(s: str, maxlen: int = 160) -> str:
        return (s if len(s) <= maxlen else s[: maxlen - 1] + "…")

    for b, items in grouped.items():
        total = len(items)
        terms_set = sorted({it["term"] for it in items})
        terms_str = ", ".join(terms_set)

        N = 8
        lines = []
        for it in items[:N]:
            ex_url = it["image_url"]
            host_pg = it["host_page"] or "(no host page)"
            lines.append(f"- {format_line(ex_url)}  (via {format_line(host_pg)})")

        extra = total - len(lines)
        extra_line = f"\n… and {extra} more matches" if extra > 0 else ""

        msg = (
            f"**DMCA Monitor — {b}**\n"
            f"Matches: **{total}**  |  Terms: {terms_str}\n"
            + "\n".join(lines)
            + extra_line
        )
        notify_discord(msg)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    main(args.config)

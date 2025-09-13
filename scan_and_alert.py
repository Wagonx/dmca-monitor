import argparse, os, json
import yaml
import requests
from bs4 import BeautifulSoup
from PIL import Image
from datetime import datetime
from urllib.parse import urljoin, urlparse
from utils import (
    ensure_dirs, load_json, save_json, compute_hashes, any_distance_below,
    download_image, log_match, ssim_match, discord_notify
)

def bing_image_search(api_key: str, query: str, market: str, count: int):
    url = "https://api.bing.microsoft.com/v7.0/images/search"
    headers = {"Ocp-Apim-Subscription-Key": api_key}
    params = {"q": query, "mkt": market, "count": count, "safeSearch": "Off"}
    r = requests.get(url, headers=headers, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    results = []
    for v in data.get("value", []):
        cu = v.get("contentUrl")
        hp = v.get("hostPageUrl")
        if cu:
            results.append((cu, hp))
    return results

def bing_web_search(api_key: str, query: str, market: str, count: int):
    url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": api_key}
    params = {"q": query, "mkt": market, "count": count, "responseFilter": "Webpages"}
    r = requests.get(url, headers=headers, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    return [w["url"] for w in data.get("webPages", {}).get("value", []) if "url" in w]

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

def main(cfg_path: str):
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    terms = cfg.get("search_terms", [])
    engines = cfg.get("engines", {})
    notify = cfg.get("notify", {})
    discord_hook = notify.get("discord_webhook", "")
    discord_username = notify.get("discord_username", None)
    discord_avatar = notify.get("discord_avatar_url", None)

    mcfg = cfg.get("match", {})
    paths = cfg.get("paths", {})
    timeouts = cfg.get("timeouts", {})

    threshold = int(mcfg.get("threshold", 7))
    use_ssim = bool(mcfg.get("use_ssim", False))

    hash_db_path = paths.get("hash_db", "db/hashes.json")
    seen_cache_path = paths.get("seen_cache", "db/seen.json")
    logs_csv = paths.get("logs_csv", "logs/matches.csv")
    downloads_dir = paths.get("downloads", "scratch/downloads")

    ensure_dirs(os.path.dirname(hash_db_path), os.path.dirname(seen_cache_path),
                os.path.dirname(logs_csv), downloads_dir)

    # known hashes: {filepath: {phash/dhash/ahash/whash}}
    with open(hash_db_path, "r", encoding="utf-8") as f:
        known_hashes = json.load(f)

    seen = load_json(seen_cache_path, default={"urls": []})
    seen_urls = set(seen.get("urls", []))

    bing_cfg = engines.get("bing", {})
    bing_enabled = bing_cfg.get("enabled", True)
    api_key = bing_cfg.get("bing_api_key", "")
    market = bing_cfg.get("market", "en-US")
    img_count = int(bing_cfg.get("image_count_per_term", 50))
    web_count = int(bing_cfg.get("web_count_per_term", 0))
    slack_hook = notify.get("slack_webhook", "")

    now = datetime.utcnow().isoformat()

    for term in terms:
        candidates = []
        if bing_enabled and api_key:
            try:
                candidates.extend(bing_image_search(api_key, term, market, img_count))
            except Exception:
                pass
            if web_count > 0:
                try:
                    pages = bing_web_search(api_key, term, market, web_count)
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
                log_match(logs_csv, row)

                msg = (f"DMCA Monitor match for '{term}':\n"
                       f"- Host: {host}\n- Image: {img_url}\n- Known file: {matched_key}")
                discord_notify(discord_hook, msg, username=discord_username,
                               avatar_url=discord_avatar)

    save_json(seen_cache_path, {"urls": sorted(list(seen_urls))})

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    main(args.config)

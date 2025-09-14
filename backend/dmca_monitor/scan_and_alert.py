import argparse, os, json, logging, re
import yaml
import requests
from bs4 import BeautifulSoup
from PIL import Image
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from collections import defaultdict

from utils import (
    ensure_dirs, load_json, save_json, compute_hashes, any_distance_below,
    download_image, log_match, ssim_match,
    init_logger_to_logs, cse_fetch_paginated, canonical_base_url,
    discord_notify, _discord_post
)
from state import load_state, save_state, upsert_match

# ---------- Google Programmable Search helpers (thin wrappers over utils.cse_fetch_paginated) ----------

def google_image_search(api_key: str, cse_id: str, query: str, count: int):
    """Return [(image_url, context_url), ...]."""
    items = cse_fetch_paginated(api_key, cse_id, query, count, search_type="image")
    results = []
    for it in items:
        link = it.get("link")
        ctx  = (it.get("image") or {}).get("contextLink") or link
        if link:
            results.append((link, ctx))
    return results

def google_web_search(api_key: str, cse_id: str, query: str, count: int):
    """Return [page_url, ...]."""
    items = cse_fetch_paginated(api_key, cse_id, query, count, search_type=None)
    urls = []
    for it in items:
        link = it.get("link")
        if link:
            urls.append(link)
    return urls

# ---------- Helpers: exclusions ----------

from urllib.parse import urlparse

def host_of(u: str) -> str:
    try:
        return (urlparse(u or "").netloc or "").lower()
    except Exception:
        return ""

def load_excluded(cfg) -> set[str]:
    xs = (cfg.get("exclude_domains") or [])
    return {d.lstrip(".").lower() for d in xs}

def is_excluded(u: str, excluded: set[str]) -> bool:
    h = host_of(u)
    return any(h == d or h.endswith("." + d) for d in excluded)

# ---------- Page image extraction ----------

def extract_images_from_page(page_url: str, timeout: int = 15):
    try:
        r = requests.get(page_url, timeout=timeout, headers={"User-Agent": "DMCA-Monitor/1.0"})
    except requests.RequestException:
        logging.debug("Page fetch error: %s", page_url)
        return []
    if r.status_code != 200:
        logging.debug("Page non-200 (%s): %s", r.status_code, page_url)
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    imgs = []
    for img in soup.find_all("img"):
        src = img.get("src") or img.get("data-src") or img.get("data-original")
        if not src:
            continue
        imgs.append(urljoin(page_url, src))
    return imgs

# ---------- Main scan ----------

def main(cfg_path: str):
    # logging to /logs/debug.log
    log_path = init_logger_to_logs("debug.log")
    logging.info("Scan start; logs at %s", log_path)

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    terms = cfg.get("search_terms", [])
    engines = cfg.get("engines", {})
    notify = cfg.get("notify", {})
    mcfg = cfg.get("match", {})
    paths = cfg.get("paths", {})
    timeouts = cfg.get("timeouts", {})

    # exclusions
    excluded = load_excluded(cfg)
    if excluded:
        logging.info("Excluding %d domain(s): %s", len(excluded), sorted(excluded))

    threshold = int(mcfg.get("threshold", 7))
    use_ssim = bool(mcfg.get("use_ssim", False))

    hash_db_path = paths.get("hash_db", "db/hashes.json")
    seen_cache_path = paths.get("seen_cache", "db/seen.json")
    alerts_state_path = paths.get("alerts_state", "db/alerts.json")
    logs_csv = paths.get("logs_csv", "logs/matches.csv")
    downloads_dir = paths.get("downloads", "scratch/downloads")

    ensure_dirs(os.path.dirname(hash_db_path), os.path.dirname(seen_cache_path),
                os.path.dirname(alerts_state_path), os.path.dirname(logs_csv), downloads_dir)

    with open(hash_db_path, "r", encoding="utf-8") as f:
        known_hashes = json.load(f)

    seen = load_json(seen_cache_path, default={"urls": []})
    seen_urls = set(seen.get("urls", []))

    alerts = load_state(alerts_state_path)

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

    def notify_discord_msg(msg: str):
        if not discord_hook or not msg:
            return
        try:
            # your utils.discord_notify handles suppression/fallback
            discord_notify(discord_hook, msg, username=discord_username, avatar_url=discord_avatar)
        except Exception:
            logging.exception("Discord notify failed")

    now = datetime.now(timezone.utc).isoformat()
    grouped = defaultdict(list)  # base domain -> list[row] (only "new" & not muted)

    req_timeout = int(timeouts.get("request", 15))

    for term in terms:
        candidates: list[tuple[str, str]] = []  # (img_url, host_page)

        if google_enabled and g_api_key and g_cse_id:
            # Add -site: exclusions right in the query to reduce noise upstream
            neg = " ".join(f"-site:{d}" for d in excluded) if excluded else ""
            q = f"{term} {neg}".strip()
            logging.debug("Query for '%s' -> '%s'", term, q)

            # Image search
            try:
                candidates.extend(google_image_search(g_api_key, g_cse_id, q, g_img_count))
            except Exception:
                logging.exception("google_image_search failed for %s", q)

            # Web search -> scrape images
            if g_web_count > 0:
                try:
                    pages = google_web_search(g_api_key, g_cse_id, q, g_web_count)
                    for p in pages:
                        if is_excluded(p, excluded):
                            logging.debug("Skip page (excluded): %s", p)
                            continue
                        for img_url in extract_images_from_page(p, timeout=req_timeout):
                            candidates.append((img_url, p))
                except Exception:
                    logging.exception("google_web_search/extract failed for %s", q)

        # Dedup and filter excluded before any downloads
        seen_in_round: set[str] = set()
        filtered: list[tuple[str, str]] = []
        for img_url, host in candidates:
            if not img_url or img_url in seen_in_round:
                continue
            seen_in_round.add(img_url)

            if is_excluded(img_url, excluded) or is_excluded(host, excluded):
                logging.debug("Skip image (excluded): img=%s host=%s", img_url, host)
                continue
            filtered.append((img_url, host))

        for img_url, host in filtered:
            if img_url in seen_urls:
                logging.debug("Skip seen: %s", img_url)
                continue
            seen_urls.add(img_url)

            img = download_image(img_url, timeout=req_timeout, referer=host or None)
            if img is None:
                logging.warning("Failed download: %s", img_url)
                continue

            cand_hashes = compute_hashes(img)
            matched_key = None

            # compare with known hashes
            for kpath, khashes in known_hashes.items():
                if any_distance_below(cand_hashes, khashes, threshold):
                    if use_ssim:
                        try:
                            with Image.open(kpath).convert("RGB") as base_img:
                                if not ssim_match(base_img, img):
                                    continue
                        except Exception:
                            logging.exception("SSIM check failed for %s", kpath)
                            continue
                    matched_key = kpath
                    break

            if matched_key:
                # save a local copy (best effort)
                fname = os.path.basename(urlparse(img_url).path) or "image.jpg"
                out_path = os.path.join(downloads_dir, fname)
                try:
                    img.save(out_path)
                except Exception:
                    logging.exception("Saving copy failed: %s", out_path)
                    out_path = ""

                row = {
                    "timestamp_utc": now,
                    "term": term,
                    "image_url": img_url,
                    "host_page": host or "",
                    "matched_known_file": matched_key,
                    "saved_copy": out_path,
                }

                # Always keep audit log
                log_match(logs_csv, row)

                # Update per-site alert state
                site_key = canonical_base_url(row["host_page"] or row["image_url"])
                rec = upsert_match(alerts, site_key, row["image_url"], {**row, "timestamp_utc": now})

                # Notify only if first time (status=new) and not muted
                if (rec.get("status") == "new") and (not rec.get("muted", False)):
                    grouped[site_key].append(row)
            else:
                logging.debug("No match (<=%d): %s", threshold, img_url)

    # Persist caches/state
    save_json(seen_cache_path, {"urls": sorted(list(seen_urls))})
    save_state(alerts_state_path, alerts)

    # ---- One Discord message per base domain ----
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
        notify_discord_msg(msg)
        logging.info("Notified %s with %d item(s)", b, total)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    main(args.config)

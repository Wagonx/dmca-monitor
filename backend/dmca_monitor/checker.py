import re
import time
import datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Tuple, Optional
import requests

MAX_WORKERS = 8
TIMEOUT = 12
BATCH_LIMIT = 500         # checks per tick (avoid hammering)
SLEEP_BETWEEN_REQUESTS = 0.0  # small politeness delay per URL, if desired

TAKEDOWN_HINTS = re.compile(
    r"(removed\s+due\s+to\s+copyright|dmca|not\s+available|content\s+unavailable|"
    r"has\s+been\s+deleted|page\s+not\s+found|violat(e|ion)|terms\s+of\s+service)",
    re.IGNORECASE,
)

HEADERS = {
    "User-Agent": "DMCA-Monitor/1.0 (+contact: you@domain.tld)",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
}

def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def looks_gone(code: int, text: Optional[str]) -> bool:
    if code in (404, 410, 451):
        return True
    if code in (401, 403):
        return False
    if 300 <= code < 400:
        return False
    if code == 200 and text and TAKEDOWN_HINTS.search(text):
        return True
    return False

def fetch_status(url: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Return (http_status, body_text_if_html, fail_reason).
    Prefer GET (HEAD is often misconfigured).
    """
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        ctype = r.headers.get("content-type", "")
        text = r.text if ("text" in ctype and 200 <= r.status_code < 400) else None
        return r.status_code, text, None
    except requests.RequestException as e:
        return None, None, f"http_error:{type(e).__name__}:{str(e)[:300]}"
    except Exception as e:
        return None, None, f"unknown_error:{type(e).__name__}:{str(e)[:300]}"

def iter_matches_from_state(state: Dict):
    """
    Yields (domain, image_url, match_meta_dict). Only returns dicts so we can mutate safely.
    Expected structure:
      state["sites"][domain]["matches"][image_url] -> { ...fields... }
    """
    sites = state.get("sites", {}) or {}
    for domain, sdata in sites.items():
        matches = (sdata or {}).get("matches", {}) or {}
        for image_url, meta in matches.items():
            # Ensure meta is a dict we can modify
            if isinstance(meta, dict):
                yield domain, image_url, meta

def check_one(image_url: str) -> Dict[str, Optional[str]]:
    # politeness pacing if needed
    if SLEEP_BETWEEN_REQUESTS:
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    code, text, fail = fetch_status(image_url)
    now = _now_iso()
    out = {
        "http_status": code,
        "fail_reason": fail,
        "last_checked_utc": now,
        "last_seen_utc": None,
        "removed_at_utc": None,
        "status": None,
    }
    if fail is not None:
        out["status"] = "error"
        return out

    if looks_gone(code or 0, text):
        out["status"] = "gone"
        out["removed_at_utc"] = now
    else:
        out["status"] = "up"
        out["last_seen_utc"] = now
    return out

def run_once(get_state: Callable[[], Dict], set_state: Callable[[Dict], None]) -> int:
    """
    Loads JSON, checks up to BATCH_LIMIT matches in parallel, updates JSON, saves.
    Returns number of processed URLs.
    """
    state = get_state() or {}
    jobs = []
    targets = []
    for i, (domain, image_url, _) in enumerate(iter_matches_from_state(state)):
        if i >= BATCH_LIMIT:
            break
        targets.append((domain, image_url))

    if not targets:
        return 0

    results: Dict[Tuple[str, str], Dict] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_map = {pool.submit(check_one, url): (domain, url) for domain, url in targets}
        for fut in as_completed(future_map):
            domain, url = future_map[fut]
            try:
                results[(domain, url)] = fut.result()
            except Exception as e:
                results[(domain, url)] = {
                    "http_status": None,
                    "fail_reason": f"worker_error:{type(e).__name__}:{str(e)[:300]}",
                    "last_checked_utc": _now_iso(),
                    "last_seen_utc": None,
                    "removed_at_utc": None,
                    "status": "error",
                }

    # merge back into state
    for (domain, url), res in results.items():
        meta = state.setdefault("sites", {}).setdefault(domain, {}).setdefault("matches", {}).setdefault(url, {})
        # preserve manual fields like notes/muted/status overrides when reasonable
        meta["http_status"] = res["http_status"]
        meta["fail_reason"] = res["fail_reason"]
        meta["last_checked_utc"] = res["last_checked_utc"]
        if res["status"] == "up":
            meta["status"] = "up" if meta.get("status") not in ("closed", "ack") else meta["status"]
            meta["last_seen_utc"] = res["last_seen_utc"]
            meta.pop("removed_at_utc", None)
        elif res["status"] == "gone":
            # don’t clobber if user already closed/acked; still record removed time
            if meta.get("status") not in ("closed", "ack"):
                meta["status"] = "gone"
            meta["removed_at_utc"] = res["removed_at_utc"]
        else:
            meta["status"] = "error"

    set_state(state)
    return len(results)

def install_scheduler(app, get_state: Callable[[], Dict], set_state: Callable[[Dict], None], interval_seconds: int = 600):
    """
    Wire a BackgroundScheduler into your Flask app.
    """
    from apscheduler.schedulers.background import BackgroundScheduler
    scheduler = BackgroundScheduler(daemon=True)

    def job():
        try:
            n = run_once(get_state, set_state)
            if n:
                app.logger.info(f"[DMCA Recheck] processed {n} URL(s)")
        except Exception as e:
            app.logger.exception(f"[DMCA Recheck] error: {e}")

    scheduler.add_job(job, "interval", seconds=interval_seconds, next_run_time=dt.datetime.now() + dt.timedelta(seconds=15))
    scheduler.start()
    app.logger.info("[DMCA Recheck] scheduler installed")
    return scheduler

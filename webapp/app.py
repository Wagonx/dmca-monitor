import csv
import os
from collections import defaultdict
from urllib.parse import urlparse
from flask import Flask, render_template, send_from_directory, abort, request, redirect, url_for, flash
from dmca_monitor.state import load_state, save_state, upsert_match

# --------- Paths (adjust if you moved things) ----------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOGS_CSV = os.path.join(PROJECT_ROOT, "logs", "matches.csv")
DOWNLOADS_DIR = os.path.join(PROJECT_ROOT, "scratch", "downloads")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_JSON = os.path.join(PROJECT_ROOT, "db", "alerts.json")


app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

def get_state():
    return load_state(ALERTS_JSON)

def set_state(s):
    save_state(ALERTS_JSON, s)


def base_url(u: str) -> str:
    try:
        p = urlparse(u or "")
        if p.netloc:
            return p.netloc.lower()
        return (u or "").lower()
    except Exception:
        return "(unknown)"

def read_logs():
    rows = []
    if not os.path.exists(LOGS_CSV):
        return rows
    with open(LOGS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows

def _rel_download_name(p: str) -> str:
    if not p:
        return ""
    norm = os.path.normpath(p)
    try:
        rel = os.path.relpath(norm, DOWNLOADS_DIR)
        # turn backslashes into URL-friendly slashes
        return rel.replace("\\", "/")
    except ValueError:
        # e.g., different drive on Windows → fallback to basename
        return os.path.basename(norm)

def _ensure_match_in_state(domain: str, image_url: str):
    """Create/merge a match in alerts state from logs if missing; return (state, site, match)."""
    s = get_state()
    d = domain.lower()
    site = s.setdefault("sites", {}).setdefault(d, {"matches": {}})
    if image_url not in site["matches"]:
        # pull the row from logs to seed payload fields
        row = next((r for r in read_logs() if r.get("image_url") == image_url), {})
        upsert_match(s, d, image_url, {
            "timestamp_utc": row.get("timestamp_utc"),
            "host_page": row.get("host_page"),
            "term": row.get("term"),
            "matched_known_file": row.get("matched_known_file"),
            "saved_copy": row.get("saved_copy"),
        })
        site = s["sites"][d]
    return s, site, site["matches"][image_url]

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/logs")
def view_logs():
    rows = read_logs()
    # newest first
    rows.sort(key=lambda r: r.get("timestamp_utc",""), reverse=True)
    return render_template("logs.html", rows=rows)

@app.route("/sites")
def sites():
    rows = read_logs()
    groups = defaultdict(list)
    for r in rows:
        host = r.get("host_page") or r.get("image_url") or ""
        groups[base_url(host)].append(r)

    # list of dicts: [{domain, count, terms_set}]
    data = []
    for dom, items in groups.items():
        terms = sorted({i.get("term","") for i in items if i.get("term")})
        data.append({
            "domain": dom or "(unknown)",
            "count": len(items),
            "terms": ", ".join(terms),
        })
    data.sort(key=lambda d: d["count"], reverse=True)
    return render_template("sites.html", sites=data)

@app.route("/sites/<domain>")
def site_detail(domain: str):
    rows = read_logs()
    domain_l = domain.lower()

    # join with alerts state
    alerts = get_state().get("sites", {}).get(domain_l, {}).get("matches", {})

    matches = []
    for r in rows:
        host = r.get("host_page") or r.get("image_url") or ""
        if base_url(host).replace("http://","").replace("https://","").lower() == domain_l:
            meta = alerts.get(r.get("image_url"), {}) or {}
            # compute a relative, URL-safe path for saved copies
            saved = (meta.get("saved_copy") or r.get("saved_copy") or "")
            rel = ""
            if saved:
                rel = os.path.normpath(saved).replace("\\", "/")
                if "scratch/downloads/" in rel:
                    rel = rel.split("scratch/downloads/")[-1]
            r_with_meta = {**r, "_meta": meta, "_saved_rel": rel}
            matches.append(r_with_meta)

    matches.sort(key=lambda r: r.get("timestamp_utc",""), reverse=True)
    return render_template("site_detail.html",
                           domain=domain,
                           matches=matches)
@app.post("/sites/<domain>/match/ack")
def ack_match(domain):
    image_url = request.form.get("image_url") or ""
    s, site, m = _ensure_match_in_state(domain, image_url)
    m["status"] = "ack"
    set_state(s)
    return redirect(url_for("site_detail", domain=domain))

@app.post("/sites/<domain>/match/close")
def close_match(domain):
    image_url = request.form.get("image_url") or ""
    s, site, m = _ensure_match_in_state(domain, image_url)
    m["status"] = "closed"
    set_state(s)
    return redirect(url_for("site_detail", domain=domain))

@app.post("/sites/<domain>/match/mute")
def mute_match(domain):
    image_url = request.form.get("image_url") or ""
    s, site, m = _ensure_match_in_state(domain, image_url)
    m["muted"] = not bool(m.get("muted"))
    set_state(s)
    return redirect(url_for("site_detail", domain=domain))

@app.post("/sites/<domain>/match/note")
def note_match(domain):
    image_url = request.form.get("image_url") or ""
    text = (request.form.get("note") or "").strip()
    if not text:
        return redirect(url_for("site_detail", domain=domain))
    s, site, m = _ensure_match_in_state(domain, image_url)
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat()
    m.setdefault("notes", []).append({"ts": ts, "text": text})
    set_state(s)
    return redirect(url_for("site_detail", domain=domain))

@app.route("/downloads/<path:filename>")
def downloads(filename: str):
    # serve local saved copies (thumbnails/full) from scratch/downloads
    safe_root = os.path.realpath(DOWNLOADS_DIR)
    requested = os.path.realpath(os.path.join(DOWNLOADS_DIR, filename))
    if not requested.startswith(safe_root):
        abort(404)
    if not os.path.exists(requested):
        abort(404)
    directory = os.path.dirname(requested)
    fname = os.path.basename(requested)
    return send_from_directory(directory, fname)



if __name__ == "__main__":
    # Simple dev server
    app.run(host="127.0.0.1", port=5000, debug=True)

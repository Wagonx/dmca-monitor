import csv
import os
from collections import defaultdict
from urllib.parse import urlparse
from flask import Flask, render_template, send_from_directory, abort, request, redirect, url_for, flash
from dmca_monitor.state import load_state, save_state
from dmca_monitor.checker import install_scheduler
from datetime import datetime




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

install_scheduler(
    app,
    get_state=get_state,
    set_state=set_state,
    interval_seconds=600,   # every 10 minutes; tune as needed
)

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
            meta = alerts.get(r.get("image_url"), {})
            matches.append({**r, "_meta": meta})

    matches.sort(key=lambda r: r.get("timestamp_utc",""), reverse=True)
    return render_template("site_detail.html",
                           domain=domain,
                           matches=matches,
                           downloads_base="/downloads")

@app.post("/sites/<domain>/match/ack")
def ack_match(domain):
    image_url = request.form.get("image_url")
    s = get_state()
    site = s.get("sites", {}).get(domain.lower())
    if not site or image_url not in site.get("matches", {}):
        abort(404)
    site["matches"][image_url]["status"] = "ack"
    set_state(s)
    return redirect(url_for("site_detail", domain=domain))

@app.post("/sites/<domain>/match/close")
def close_match(domain):
    image_url = request.form.get("image_url")
    s = get_state()
    site = s.get("sites", {}).get(domain.lower())
    if not site or image_url not in site.get("matches", {}):
        abort(404)
    site["matches"][image_url]["status"] = "closed"
    set_state(s)
    return redirect(url_for("site_detail", domain=domain))

@app.post("/sites/<domain>/match/mute")
def mute_match(domain):
    image_url = request.form.get("image_url")
    s = get_state()
    site = s.get("sites", {}).get(domain.lower())
    if not site or image_url not in site.get("matches", {}):
        abort(404)
    m = site["matches"][image_url]
    m["muted"] = not bool(m.get("muted"))
    set_state(s)
    return redirect(url_for("site_detail", domain=domain))

@app.post("/sites/<domain>/match/note")
def note_match(domain):
    image_url = request.form.get("image_url")
    text = (request.form.get("note") or "").strip()
    if not text:
        return redirect(url_for("site_detail", domain=domain))
    s = get_state()
    site = s.get("sites", {}).get(domain.lower())
    if not site or image_url not in site.get("matches", {}):
        abort(404)
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat()
    site["matches"][image_url].setdefault("notes", []).append({"ts": ts, "text": text})
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

@app.route("/admin/recheck-now", methods=["GET", "POST"])
def recheck_now():
    from dmca_monitor.checker import run_once
    n = run_once(get_state, set_state)
    return {"processed": n}, 200

@app.template_filter("fmt_dt")
def fmt_dt(value):
    """Format ISO datetime string into something friendlier like 2025-09-14 20:37"""
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value  # fallback if parsing fails

if __name__ == "__main__":
    # Simple dev server
    app.run(host="127.0.0.1", port=5000, debug=True)

#!/usr/bin/env python3
"""
SOC Dashboard - Build Your Own Mini SIEM Front-End
=====================================================
A self-contained Flask + SQLite SOC/SIEM demonstration dashboard.

FOR USE IN ISOLATED CYBERSECURITY LAB ENVIRONMENTS WITH SYNTHETIC DATA ONLY.
Do not use this application to monitor real systems or networks without
explicit authorization.

Run with:
    pip install flask werkzeug
    python dashboard.py
"""

import os
import re
import csv
import io
import json
import random
import secrets
import sqlite3
import threading
import time
import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, jsonify, g, flash, Response
)
from werkzeug.security import generate_password_hash, check_password_hash

# =====================================================================
# CONFIGURATION
# =====================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_secret_key():
    """Return a persistent, unguessable session signing key.

    The key must survive restarts, otherwise every restart invalidates all
    sessions, but it must never be committed. There is no hardcoded default:
    the value comes from SOC_SECRET_KEY, or is generated once and cached in a
    restricted file next to the application.
    """
    env_key = os.environ.get("SOC_SECRET_KEY")
    if env_key:
        return env_key

    key_file = os.path.join(BASE_DIR, ".secret_key")
    try:
        with open(key_file, "r", encoding="utf-8") as fh:
            cached = fh.read().strip()
        if len(cached) >= 32:
            return cached
    except OSError:
        pass

    key = secrets.token_hex(32)
    try:
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(key)
    except OSError:
        pass
    return key


DATABASE = os.environ.get("SOC_DATABASE", os.path.join(BASE_DIR, "soc_dashboard.db"))

DEFAULT_ADMIN_USERNAME = "admin"
# No password ships with the repository. On first run a random one is generated,
# printed once to the console, and stored only as a scrypt hash. Override it with
# SOC_ADMIN_PASSWORD before the first launch if you need a known value.
DEFAULT_ADMIN_PASSWORD = None

DEFAULT_THRESHOLD = 5          # number of suspicious events to trigger an alert
DEFAULT_TIME_WINDOW_MIN = 5    # minutes
DEFAULT_REFRESH_INTERVAL = 15  # seconds

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SUSPICIOUS_EVENT_TYPES = {
    "Failed SSH Login", "Multiple Failed Login Attempts", "Port Scan Detected",
    "Suspicious Network Connection", "Malware Detection", "Brute Force Attempt",
    "C2 Communication Suspected", "IDS Alert", "Firewall Blocked Connection",
    "Suricata Alert",
}

app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SOC_COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=8),
)

# =====================================================================
# CSRF PROTECTION
# =====================================================================
# Every state-changing request must carry a per-session token. Without this a
# third-party page could make an authenticated analyst's browser clear the log
# database or change detection thresholds.

CSRF_SESSION_KEY = "csrf_token"


def csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def csrf_input():
    return f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'


app.jinja_env.globals["csrf_input"] = csrf_input


@app.before_request
def verify_csrf():
    if request.method != "POST":
        return None
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get(CSRF_SESSION_KEY, "")
    if not expected or not secrets.compare_digest(str(submitted), str(expected)):
        return (
            "<!doctype html><meta charset='utf-8'>"
            "<h1>400 — Bad Request</h1>"
            "<p>The CSRF token was missing or invalid. "
            "Reload the page and try again.</p>",
            400,
        )
    return None


# =====================================================================
# LOGIN THROTTLING
# =====================================================================
# Deliberately simple single-process throttle. It slows online password guessing
# on a lab deployment; it is not a distributed rate limiter.

LOGIN_MAX_ATTEMPTS = int(os.environ.get("SOC_LOGIN_MAX_ATTEMPTS", "10"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("SOC_LOGIN_WINDOW_SECONDS", "300"))

_login_failures = {}
_login_lock = threading.Lock()


def _login_throttled(client_ip):
    now = time.monotonic()
    with _login_lock:
        attempts = [t for t in _login_failures.get(client_ip, []) if now - t < LOGIN_WINDOW_SECONDS]
        _login_failures[client_ip] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _record_login_failure(client_ip):
    with _login_lock:
        _login_failures.setdefault(client_ip, []).append(time.monotonic())


# =====================================================================
# DATABASE HELPERS
# =====================================================================

def get_db():
    """Get a per-request SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed default data if the database does not exist yet."""
    first_run = not os.path.exists(DATABASE)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port TEXT,
            event_type TEXT,
            severity TEXT,
            raw_message TEXT,
            alert_status TEXT DEFAULT 'NONE',
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    conn.commit()

    # Seed the administrator account. No password ships in the repository: a
    # random one is generated on first run, printed once, and stored only as a
    # scrypt hash.
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        generated_password = os.environ.get("SOC_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (
                DEFAULT_ADMIN_USERNAME,
                generate_password_hash(generated_password),
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        if not os.environ.get("SOC_ADMIN_PASSWORD"):
            print()
            print("=" * 72)
            print(" First run — administrator account created")
            print(f"   username : {DEFAULT_ADMIN_USERNAME}")
            print(f"   password : {generated_password}")
            print(" This password is shown once and is not stored in plaintext.")
            print(" Change it from Settings after signing in.")
            print("=" * 72)
            print()

    # Seed default settings
    default_settings = {
        "threshold": str(DEFAULT_THRESHOLD),
        "time_window_min": str(DEFAULT_TIME_WINDOW_MIN),
        "refresh_interval": str(DEFAULT_REFRESH_INTERVAL),
    }
    for k, v in default_settings.items():
        cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
    conn.commit()

    # Seed a handful of demo logs on first run
    cur.execute("SELECT COUNT(*) AS c FROM logs")
    if cur.fetchone()["c"] == 0:
        conn.close()
        _generate_sample_logs(20)
    else:
        conn.close()


_schema_ready = False


@app.before_request
def ensure_schema():
    """Create and seed the schema once per process, before the first request.

    ``python dashboard.py`` calls :func:`init_db` directly. This hook covers the
    other entry points — ``flask run``, a WSGI server, or a database file that
    disappeared while the process was alive — so the first request cannot fail
    with ``no such table: logs``.
    """
    global _schema_ready
    if not _schema_ready:
        init_db()
        _schema_ready = True


def get_setting(key, default=None):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    return row["value"]


def set_setting(key, value):
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )
    db.commit()


# =====================================================================
# AUTH HELPERS
# =====================================================================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def _safe_next_url(default_endpoint="dashboard"):
    """Return a site-relative redirect target, or the dashboard.

    ``?next=`` is attacker-controllable, so anything with a scheme, a host, or a
    protocol-relative prefix is discarded. Without this check the login page is
    an open redirect and a useful phishing primitive.
    """
    candidate = request.args.get("next", "")
    if candidate:
        parsed = urlparse(candidate)
        if (not parsed.scheme and not parsed.netloc
                and candidate.startswith("/") and not candidate.startswith("//")):
            return candidate
    return url_for(default_endpoint)



# =====================================================================
# LOG NORMALIZATION / PARSING
# =====================================================================

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_REGEX = re.compile(r"\bport[:\s]+(\d{1,5})\b", re.IGNORECASE)
TIMESTAMP_REGEX = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
)

EVENT_KEYWORDS = [
    (re.compile(r"multiple failed login", re.I), "Multiple Failed Login Attempts", "HIGH"),
    (re.compile(r"failed (ssh )?login|authentication failure|invalid user", re.I), "Failed SSH Login", "MEDIUM"),
    (re.compile(r"successful (ssh )?login|accepted password", re.I), "Successful SSH Login", "LOW"),
    (re.compile(r"port scan", re.I), "Port Scan Detected", "HIGH"),
    (re.compile(r"suspicious.*connection|unusual outbound", re.I), "Suspicious Network Connection", "MEDIUM"),
    (re.compile(r"malware|trojan|virus detected", re.I), "Malware Detection", "CRITICAL"),
    (re.compile(r"brute[\s-]?force", re.I), "Brute Force Attempt", "HIGH"),
    (re.compile(r"c2|command and control|beacon", re.I), "C2 Communication Suspected", "CRITICAL"),
    (re.compile(r"ids alert|intrusion detected", re.I), "IDS Alert", "HIGH"),
    (re.compile(r"firewall.*(blocked|denied|drop)", re.I), "Firewall Blocked Connection", "LOW"),
    (re.compile(r"suricata", re.I), "Suricata Alert", "HIGH"),
]


def parse_log_line(line):
    """
    Attempt to parse a single raw log line into a normalized dict.
    Never raises - falls back to safe defaults on any parsing failure.
    """
    result = {
        "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds"),
        "source_ip": "0.0.0.0",
        "destination_ip": None,
        "destination_port": None,
        "event_type": "Unknown Event",
        "severity": "LOW",
        "raw_message": line.strip() if isinstance(line, str) else str(line),
    }

    try:
        if not line or not str(line).strip():
            return None  # skip blank lines

        text = str(line).strip()

        # Try CSV format: timestamp,source_ip,dest_ip,event_type,severity,message
        if "," in text and text.count(",") >= 3:
            parts = [p.strip() for p in text.split(",")]
            if len(parts) >= 4 and TIMESTAMP_REGEX.match(parts[0] or ""):
                result["timestamp"] = parts[0] or result["timestamp"]
                if len(parts) > 1 and IP_REGEX.match(parts[1] or ""):
                    result["source_ip"] = parts[1]
                if len(parts) > 2 and IP_REGEX.match(parts[2] or ""):
                    result["destination_ip"] = parts[2]
                if len(parts) > 3:
                    result["event_type"] = parts[3]
                if len(parts) > 4 and parts[4].upper() in SEVERITY_LEVELS:
                    result["severity"] = parts[4].upper()
                if len(parts) > 5:
                    result["raw_message"] = ",".join(parts[5:])
                return result

        # Generic free-text parsing
        ts_match = TIMESTAMP_REGEX.search(text)
        if ts_match:
            result["timestamp"] = ts_match.group(0).replace(" ", "T")

        ips = IP_REGEX.findall(text)
        if ips:
            result["source_ip"] = ips[0]
            if len(ips) > 1:
                result["destination_ip"] = ips[1]

        port_match = PORT_REGEX.search(text)
        if port_match:
            result["destination_port"] = port_match.group(1)

        matched = False
        for pattern, event_type, severity in EVENT_KEYWORDS:
            if pattern.search(text):
                result["event_type"] = event_type
                result["severity"] = severity
                matched = True
                break

        if not matched:
            result["event_type"] = "Generic Log Entry"
            result["severity"] = "LOW"

        result["raw_message"] = text
        return result

    except Exception as exc:  # noqa: BLE001 - defensive: never crash on bad input
        result["raw_message"] = f"[PARSE ERROR: {exc}] {line}"
        return result


def insert_log(entry):
    """Insert a normalized log entry into the database and run alert detection."""
    db = get_db()
    now = datetime.datetime.utcnow().isoformat()
    cur = db.execute(
        """INSERT INTO logs
           (timestamp, source_ip, destination_ip, destination_port,
            event_type, severity, raw_message, alert_status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'NONE', ?)""",
        (
            entry.get("timestamp"),
            entry.get("source_ip"),
            entry.get("destination_ip"),
            entry.get("destination_port"),
            entry.get("event_type"),
            entry.get("severity"),
            entry.get("raw_message"),
            now,
        ),
    )
    db.commit()
    return cur.lastrowid


# =====================================================================
# ALERT DETECTION LOGIC
# =====================================================================

def run_alert_detection():
    """
    Threshold-based detection engine.
    - Brute force: >=N failed-login-style events from same source IP within window.
    - Port scan: same source IP hitting many distinct destination ports within window.
    - Suspicious activity: repeated suspicious events from same IP within window.
    Marks matching rows' alert_status and bumps severity where appropriate.
    """
    db = get_db()
    threshold = int(get_setting("threshold", DEFAULT_THRESHOLD))
    window_min = int(get_setting("time_window_min", DEFAULT_TIME_WINDOW_MIN))

    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(minutes=window_min)).isoformat()

    # --- Brute force detection ---
    rows = db.execute(
        """SELECT source_ip, COUNT(*) as cnt FROM logs
           WHERE event_type IN ('Failed SSH Login', 'Multiple Failed Login Attempts', 'Brute Force Attempt')
           AND created_at >= ?
           GROUP BY source_ip HAVING cnt >= ?""",
        (cutoff, threshold),
    ).fetchall()
    for row in rows:
        db.execute(
            """UPDATE logs SET alert_status = 'ALERT', severity = 'CRITICAL'
               WHERE source_ip = ? AND event_type IN
               ('Failed SSH Login','Multiple Failed Login Attempts','Brute Force Attempt')
               AND created_at >= ?""",
            (row["source_ip"], cutoff),
        )

    # --- Port scan detection: many distinct destination ports from one source IP ---
    rows = db.execute(
        """SELECT source_ip, COUNT(DISTINCT destination_port) as ports FROM logs
           WHERE destination_port IS NOT NULL AND created_at >= ?
           GROUP BY source_ip HAVING ports >= ?""",
        (cutoff, threshold),
    ).fetchall()
    for row in rows:
        db.execute(
            """UPDATE logs SET alert_status = 'ALERT', severity = 'HIGH'
               WHERE source_ip = ? AND destination_port IS NOT NULL AND created_at >= ?
               AND severity != 'CRITICAL'""",
            (row["source_ip"], cutoff),
        )

    # --- General suspicious activity ---
    placeholders = ",".join("?" * len(SUSPICIOUS_EVENT_TYPES))
    rows = db.execute(
        f"""SELECT source_ip, COUNT(*) as cnt FROM logs
            WHERE event_type IN ({placeholders}) AND created_at >= ?
            GROUP BY source_ip HAVING cnt >= ?""",
        (*SUSPICIOUS_EVENT_TYPES, cutoff, threshold),
    ).fetchall()
    for row in rows:
        db.execute(
            f"""UPDATE logs SET alert_status = 'ALERT'
                WHERE source_ip = ? AND event_type IN ({placeholders}) AND created_at >= ?
                AND alert_status = 'NONE'""",
            (row["source_ip"], *SUSPICIOUS_EVENT_TYPES, cutoff),
        )

    db.commit()


# =====================================================================
# SAMPLE / DEMO LOG GENERATION
# =====================================================================

def _random_lab_ip():
    choice = random.choice(["192.168", "10", "172.16"])
    if choice == "192.168":
        return f"192.168.{random.randint(0,20)}.{random.randint(1,254)}"
    if choice == "10":
        return f"10.{random.randint(0,20)}.{random.randint(0,20)}.{random.randint(1,254)}"
    return f"172.16.{random.randint(0,20)}.{random.randint(1,254)}"


SAMPLE_EVENTS = [
    ("Failed SSH Login", "MEDIUM", "Failed password for invalid user from {src} port {port} ssh2"),
    ("Successful SSH Login", "LOW", "Accepted password for labuser from {src} port {port} ssh2"),
    ("Multiple Failed Login Attempts", "HIGH", "5 failed login attempts detected from {src} within 2 minutes"),
    ("Port Scan Detected", "HIGH", "Port scan detected from {src} targeting {dst} across multiple ports"),
    ("Suspicious Network Connection", "MEDIUM", "Suspicious outbound connection from {src} to {dst}:{port}"),
    ("Malware Detection", "CRITICAL", "Malware signature matched on host {dst}, originating traffic from {src}"),
    ("Brute Force Attempt", "HIGH", "Brute force attempt detected against SSH service from {src}"),
    ("C2 Communication Suspected", "CRITICAL", "Possible C2 beacon traffic from {src} to {dst}:{port}"),
    ("IDS Alert", "HIGH", "IDS signature triggered: ET SCAN Potential SSH Scan from {src}"),
    ("Firewall Blocked Connection", "LOW", "Firewall blocked connection attempt from {src} to {dst}:{port}"),
    ("Suricata Alert", "HIGH", "Suricata alert: ET POLICY Suspicious traffic pattern from {src}"),
]


def _generate_sample_logs(count=15):
    """Generate synthetic lab log entries directly (works even outside app context)."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    now = datetime.datetime.utcnow()

    # Occasionally cluster events from the same IP to demonstrate alerting
    burst_ip = _random_lab_ip()

    for i in range(count):
        use_burst = random.random() < 0.35
        src = burst_ip if use_burst else _random_lab_ip()
        dst = _random_lab_ip()
        port = random.choice([22, 80, 443, 3389, 8080, 21, 23, 445, 3306, 5432])
        event_type, severity, template = random.choice(SAMPLE_EVENTS)
        message = template.format(src=src, dst=dst, port=port)
        ts = now - datetime.timedelta(minutes=random.randint(0, 240))

        conn.execute(
            """INSERT INTO logs
               (timestamp, source_ip, destination_ip, destination_port,
                event_type, severity, raw_message, alert_status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'NONE', ?)""",
            (
                ts.isoformat(timespec="seconds"),
                src, dst, str(port), event_type, severity,
                f"[SYNTHETIC LAB DATA] {message}",
                datetime.datetime.utcnow().isoformat(),
            ),
        )
    conn.commit()
    conn.close()


# =====================================================================
# TEMPLATES (embedded)
# =====================================================================

BASE_CSS = """
:root {
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-card: #1c222b;
  --border-color: #2d333b;
  --text-primary: #e6edf3;
  --text-secondary: #8b949e;
  --accent-blue: #58a6ff;
  --accent-green: #3fb950;
  --accent-yellow: #d29922;
  --accent-orange: #db6d28;
  --accent-red: #f85149;
  --sev-low: #3fb950;
  --sev-medium: #d29922;
  --sev-high: #db6d28;
  --sev-critical: #f85149;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  min-height: 100vh;
}
a { color: inherit; text-decoration: none; }
.layout { display: flex; min-height: 100vh; }
.sidebar {
  width: 230px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border-color);
  padding: 20px 0;
  flex-shrink: 0;
}
.sidebar .brand {
  padding: 0 20px 20px 20px;
  font-size: 18px;
  font-weight: 700;
  color: var(--accent-blue);
  border-bottom: 1px solid var(--border-color);
  margin-bottom: 10px;
}
.sidebar .brand span { display: block; font-size: 11px; color: var(--text-secondary); font-weight: 400; margin-top: 2px; }
.sidebar nav a {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 20px;
  color: var(--text-secondary);
  font-size: 14px;
  border-left: 3px solid transparent;
}
.sidebar nav a:hover, .sidebar nav a.active {
  background: var(--bg-card);
  color: var(--text-primary);
  border-left-color: var(--accent-blue);
}
.main { flex: 1; padding: 24px 32px; overflow-x: auto; }
.topbar {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 24px; flex-wrap: wrap; gap: 12px;
}
.topbar h1 { font-size: 22px; font-weight: 600; }
.topbar .user-info { color: var(--text-secondary); font-size: 13px; }
.cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 18px;
}
.card .label { color: var(--text-secondary); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.card .value { font-size: 28px; font-weight: 700; margin-top: 6px; }
.card.critical .value { color: var(--sev-critical); }
.card.high .value { color: var(--sev-high); }
.card.accent .value { color: var(--accent-blue); }
.panel {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 18px;
  margin-bottom: 24px;
}
.panel h2 { font-size: 15px; margin-bottom: 14px; font-weight: 600; color: var(--text-primary); }
.charts-grid {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 16px;
  margin-bottom: 24px;
}
@media (max-width: 900px) { .charts-grid { grid-template-columns: 1fr; } .layout { flex-direction: column; } .sidebar { width: 100%; } }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border-color); }
th { color: var(--text-secondary); font-weight: 600; text-transform: uppercase; font-size: 11px; }
tr:hover { background: rgba(255,255,255,0.02); }
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 12px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;
}
.badge-LOW { background: rgba(63,185,80,0.15); color: var(--sev-low); }
.badge-MEDIUM { background: rgba(210,153,34,0.15); color: var(--sev-medium); }
.badge-HIGH { background: rgba(219,109,40,0.15); color: var(--sev-high); }
.badge-CRITICAL { background: rgba(248,81,73,0.2); color: var(--sev-critical); font-weight: 800; animation: pulse 1.6s infinite; }
.badge-ALERT { background: rgba(248,81,73,0.2); color: var(--sev-critical); }
.badge-NONE { background: rgba(139,148,158,0.15); color: var(--text-secondary); }
@keyframes pulse { 0%{opacity:1;} 50%{opacity:0.6;} 100%{opacity:1;} }
.row-critical { border-left: 3px solid var(--sev-critical); }
.btn {
  display: inline-block; padding: 9px 16px; border-radius: 6px; border: 1px solid var(--border-color);
  background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 13px; font-weight: 500;
}
.btn:hover { background: #22283154; }
.btn-primary { background: var(--accent-blue); border-color: var(--accent-blue); color: #05121f; font-weight: 700; }
.btn-danger { background: var(--sev-critical); border-color: var(--sev-critical); color: #2a0505; font-weight: 700; }
.btn-row { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
input, select, textarea {
  background: var(--bg-secondary); border: 1px solid var(--border-color); color: var(--text-primary);
  padding: 9px 12px; border-radius: 6px; font-size: 13px; width: 100%;
}
label { font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px; }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 16px; }
.login-wrap { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.login-box {
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px;
  padding: 36px; width: 360px;
}
.login-box h1 { font-size: 20px; margin-bottom: 4px; color: var(--accent-blue); }
.login-box p.subtitle { color: var(--text-secondary); font-size: 13px; margin-bottom: 20px; }
.alert-banner {
  background: rgba(210,153,34,0.12); border: 1px solid var(--accent-yellow); color: var(--accent-yellow);
  padding: 10px 14px; border-radius: 6px; font-size: 12px; margin-bottom: 16px;
}
.flash { padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; }
.flash-error { background: rgba(248,81,73,0.15); color: var(--sev-critical); border: 1px solid var(--sev-critical); }
.flash-success { background: rgba(63,185,80,0.15); color: var(--sev-low); border: 1px solid var(--sev-low); }
.text-secondary { color: var(--text-secondary); }
.small { font-size: 12px; }
.mb-16 { margin-bottom: 16px; }
code.inline { background: var(--bg-secondary); padding: 2px 6px; border-radius: 4px; font-size: 12px; }
.footer-note { color: var(--text-secondary); font-size: 11px; margin-top: 30px; text-align: center; }
"""

NAV_ITEMS = [
    ("dashboard", "Dashboard", "🛡"),
    ("logs_page", "Logs", "📄"),
    ("alerts_page", "Alerts", "🚨"),
    ("ingest_page", "Ingest Logs", "⬆"),
    ("settings_page", "Settings", "⚙"),
    ("about_page", "About", "ℹ"),
]

def render_page(title, body, active=None, username=None):
    nav_html = ""
    for endpoint, label, icon in NAV_ITEMS:
        cls = "active" if endpoint == active else ""
        nav_html += f'<a href="{url_for(endpoint)}" class="{cls}">{icon} {label}</a>\n'
    nav_html += f'<a href="{url_for("logout")}">🚪 Logout</a>'

    flashed = ""
    for category, message in _get_flashes():
        css = "flash-error" if category == "error" else "flash-success"
        flashed += f'<div class="flash {css}">{message}</div>'

    return render_template_string(
        PAGE_SHELL,
        title=title, body=body, nav_html=nav_html, css=BASE_CSS,
        username=username or session.get("username", ""), flashed=flashed,
    )


def _get_flashes():
    from flask import get_flashed_messages
    return [(cat, msg) for cat, msg in get_flashed_messages(with_categories=True)]


PAGE_SHELL = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} · SOC Dashboard</title>
<style>{{ css | safe }}</style>
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <div class="brand">SOC Dashboard<span>Mini SIEM · Lab Edition</span></div>
    <nav>{{ nav_html | safe }}</nav>
  </aside>
  <main class="main">
    <div class="topbar">
      <h1>{{ title }}</h1>
      <div class="user-info">Signed in as <strong>{{ username }}</strong></div>
    </div>
    {{ flashed | safe }}
    {{ body | safe }}
    <div class="footer-note">SOC Dashboard — for authorized isolated lab environments and synthetic data only.</div>
  </main>
</div>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login · SOC Dashboard</title>
<style>{{ css | safe }}</style>
</head>
<body>
<div class="login-wrap">
  <div class="login-box">
    <h1>🛡 SOC Dashboard</h1>
    <p class="subtitle">Mini SIEM — Lab Edition</p>
    <div class="alert-banner">
      Authorized lab use only. This dashboard displays synthetic security events.<br>
    </div>
    {{ flashed | safe }}
    <form method="POST" action="{{ url_for('login') }}">
      {{ csrf_input() | safe }}
      <label>Username</label>
      <input type="text" name="username" required class="mb-16" autofocus>
      <label>Password</label>
      <input type="password" name="password" required class="mb-16">
      <button type="submit" class="btn btn-primary" style="width:100%;">Sign In</button>
    </form>
  </div>
</div>
</body>
</html>
"""

# =====================================================================
# ROUTES: AUTH
# =====================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        if _login_throttled(client_ip):
            flash("Too many failed attempts. Wait a few minutes and try again.", "error")
            return render_template_string(
                LOGIN_TEMPLATE, css=BASE_CSS,
                flashed=f'<div class="flash flash-error">Too many failed attempts. '
                        f'Wait a few minutes and try again.</div>',
            ), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            with _login_lock:
                _login_failures.pop(client_ip, None)
            flash("Login successful.", "success")
            return redirect(_safe_next_url())
        _record_login_failure(client_ip)
        flash("Invalid username or password.", "error")

    flashed = ""
    for category, message in _get_flashes():
        css = "flash-error" if category == "error" else "flash-success"
        flashed += f'<div class="flash {css}">{message}</div>'
    return render_template_string(LOGIN_TEMPLATE, css=BASE_CSS, flashed=flashed)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


# =====================================================================
# ROUTES: DASHBOARD
# =====================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    refresh_interval = get_setting("refresh_interval", DEFAULT_REFRESH_INTERVAL)

    body = f"""
    <div class="btn-row">
      <form method="POST" action="{url_for('generate_sample')}" style="display:inline;">
        {csrf_input()}
        <button type="submit" class="btn btn-primary">⚡ Generate Sample Security Logs</button>
      </form>
      <button class="btn" onclick="location.reload()">🔄 Refresh Now</button>
    </div>

    <div id="summary-cards" class="cards-grid"></div>

    <div class="charts-grid">
      <div class="panel">
        <h2>Alert Volume Over Time</h2>
        <canvas id="timelineChart" height="110"></canvas>
      </div>
      <div class="panel">
        <h2>Severity Distribution</h2>
        <canvas id="severityChart" height="110"></canvas>
      </div>
    </div>

    <div class="charts-grid">
      <div class="panel">
        <h2>Top Offending Source IPs</h2>
        <table id="offendersTable"><thead><tr><th>Source IP</th><th>Event Count</th><th>Max Severity</th></tr></thead><tbody></tbody></table>
      </div>
      <div class="panel">
        <h2>Event Type Distribution</h2>
        <table id="eventTypeTable"><thead><tr><th>Event Type</th><th>Count</th></tr></thead><tbody></tbody></table>
      </div>
    </div>

    <div class="panel">
      <h2>Recent Alerts</h2>
      <div style="overflow-x:auto;">
      <table id="recentAlertsTable">
        <thead><tr><th>Time</th><th>Source IP</th><th>Event Type</th><th>Severity</th><th>Status</th><th>Message</th></tr></thead>
        <tbody></tbody>
      </table>
      </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <script>
    let timelineChart, severityChart;
    const REFRESH_MS = {refresh_interval}000;

    function sevBadge(sev) {{
      return `<span class="badge badge-${{sev}}">${{sev}}</span>`;
    }}
    function statusBadge(status) {{
      return `<span class="badge badge-${{status}}">${{status}}</span>`;
    }}

    async function loadDashboard() {{
      try {{
        const res = await fetch('/api/dashboard');
        const data = await res.json();

        const cardsHtml = `
          <div class="card accent"><div class="label">Total Logs</div><div class="value">${{data.total_logs}}</div></div>
          <div class="card"><div class="label">Total Alerts</div><div class="value">${{data.total_alerts}}</div></div>
          <div class="card critical"><div class="label">Critical Alerts</div><div class="value">${{data.critical_alerts}}</div></div>
          <div class="card high"><div class="label">High Severity</div><div class="value">${{data.high_alerts}}</div></div>
          <div class="card accent"><div class="label">Unique Source IPs</div><div class="value">${{data.unique_ips}}</div></div>
        `;
        document.getElementById('summary-cards').innerHTML = cardsHtml;

        // Recent alerts table
        let rows = '';
        data.recent_alerts.forEach(a => {{
          const rowClass = a.severity === 'CRITICAL' ? 'row-critical' : '';
          rows += `<tr class="${{rowClass}}">
            <td>${{a.timestamp}}</td><td>${{a.source_ip}}</td><td>${{a.event_type}}</td>
            <td>${{sevBadge(a.severity)}}</td><td>${{statusBadge(a.alert_status)}}</td>
            <td class="small text-secondary">${{a.raw_message}}</td></tr>`;
        }});
        document.querySelector('#recentAlertsTable tbody').innerHTML = rows || '<tr><td colspan="6" class="text-secondary">No alerts yet.</td></tr>';

        // Top offenders
        const offRes = await fetch('/api/top-offenders');
        const offData = await offRes.json();
        let offRows = '';
        offData.forEach(o => {{
          offRows += `<tr><td>${{o.source_ip}}</td><td>${{o.count}}</td><td>${{sevBadge(o.max_severity)}}</td></tr>`;
        }});
        document.querySelector('#offendersTable tbody').innerHTML = offRows || '<tr><td colspan="3" class="text-secondary">No data yet.</td></tr>';

        // Event type distribution
        let etRows = '';
        data.event_type_distribution.forEach(e => {{
          etRows += `<tr><td>${{e.event_type}}</td><td>${{e.count}}</td></tr>`;
        }});
        document.querySelector('#eventTypeTable tbody').innerHTML = etRows || '<tr><td colspan="2" class="text-secondary">No data yet.</td></tr>';

        // Timeline chart
        const tlRes = await fetch('/api/timeline');
        const tlData = await tlRes.json();
        if (timelineChart) timelineChart.destroy();
        timelineChart = new Chart(document.getElementById('timelineChart'), {{
          type: 'line',
          data: {{
            labels: tlData.labels.map(l => l.slice(5).replace('T', ' ')),
            datasets: [{{
              label: 'Events',
              data: tlData.counts,
              borderColor: '#58a6ff',
              backgroundColor: 'rgba(88,166,255,0.15)',
              fill: true,
              tension: 0.3,
            }}]
          }},
          options: {{
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
              x: {{ ticks: {{ color: '#8b949e', maxTicksLimit: 6, maxRotation: 0, autoSkip: true }}, grid: {{ color: '#2d333b' }} }},
              y: {{ ticks: {{ color: '#8b949e', precision: 0 }}, grid: {{ color: '#2d333b' }} }}
            }}
          }}
        }});

        // Severity chart
        const sevRes = await fetch('/api/severity');
        const sevData = await sevRes.json();
        if (severityChart) severityChart.destroy();
        severityChart = new Chart(document.getElementById('severityChart'), {{
          type: 'doughnut',
          data: {{
            labels: sevData.labels,
            datasets: [{{
              data: sevData.counts,
              backgroundColor: ['#3fb950', '#d29922', '#db6d28', '#f85149'],
              borderColor: '#161b22',
            }}]
          }},
          options: {{ plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#e6edf3' }} }} }} }}
        }});
      }} catch (err) {{
        console.error('Dashboard load error:', err);
      }}
    }}

    loadDashboard();
    setInterval(loadDashboard, REFRESH_MS);
    </script>
    """
    return render_page("Dashboard", body, active="dashboard")


@app.route("/generate-sample", methods=["POST"])
@login_required
def generate_sample():
    _generate_sample_logs(20)
    run_alert_detection()
    flash("20 synthetic sample security logs generated.", "success")
    return redirect(url_for("dashboard"))


# =====================================================================
# ROUTES: LOGS PAGE
# =====================================================================

@app.route("/logs")
@login_required
def logs_page():
    body = f"""
    <div class="panel">
      <h2>Search &amp; Filter Logs</h2>
      <form method="GET" action="{url_for('logs_page')}" class="form-grid">
        <div><label>Source IP</label><input type="text" name="source_ip" value="{request.args.get('source_ip','')}"></div>
        <div><label>Event Type</label><input type="text" name="event_type" value="{request.args.get('event_type','')}"></div>
        <div>
          <label>Severity</label>
          <select name="severity">
            <option value="">All</option>
            {"".join(f'<option value="{s}" {"selected" if request.args.get("severity")==s else ""}>{s}</option>' for s in SEVERITY_LEVELS)}
          </select>
        </div>
        <div>
          <label>Alert Status</label>
          <select name="alert_status">
            <option value="">All</option>
            <option value="ALERT" {"selected" if request.args.get('alert_status')=='ALERT' else ""}>ALERT</option>
            <option value="NONE" {"selected" if request.args.get('alert_status')=='NONE' else ""}>NONE</option>
          </select>
        </div>
        <div><label>From Date</label><input type="date" name="date_from" value="{request.args.get('date_from','')}"></div>
        <div><label>To Date</label><input type="date" name="date_to" value="{request.args.get('date_to','')}"></div>
        <div><label>Search Text</label><input type="text" name="q" value="{request.args.get('q','')}" placeholder="search message..."></div>
      </form>
      <div class="btn-row">
        <button type="submit" form="" class="btn btn-primary" onclick="this.closest('.panel').querySelector('form').submit()">Apply Filters</button>
        <a href="{url_for('logs_page')}" class="btn">Clear</a>
        <a href="{url_for('export_csv')}?{request.query_string.decode()}" class="btn">⬇ Export CSV</a>
        <button class="btn btn-danger" onclick="if(confirm('This will permanently delete ALL logs. Continue?')) document.getElementById('clear-form').submit();">🗑 Clear All Logs</button>
        <form id="clear-form" method="POST" action="{url_for('clear_logs')}" style="display:none;">{csrf_input()}</form>
      </div>
    </div>

    <div class="panel">
      <h2>Logs</h2>
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>Event Type</th><th>Severity</th><th>Status</th><th>Message</th><th></th></tr></thead>
        <tbody>
        {LOGS_ROWS_PLACEHOLDER}
        </tbody>
      </table>
      </div>
    </div>
    """

    db = get_db()
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    if request.args.get("source_ip"):
        query += " AND source_ip LIKE ?"
        params.append(f"%{request.args.get('source_ip')}%")
    if request.args.get("event_type"):
        query += " AND event_type LIKE ?"
        params.append(f"%{request.args.get('event_type')}%")
    if request.args.get("severity"):
        query += " AND severity = ?"
        params.append(request.args.get("severity"))
    if request.args.get("alert_status"):
        query += " AND alert_status = ?"
        params.append(request.args.get("alert_status"))
    if request.args.get("date_from"):
        query += " AND timestamp >= ?"
        params.append(request.args.get("date_from"))
    if request.args.get("date_to"):
        query += " AND timestamp <= ?"
        params.append(request.args.get("date_to") + "T23:59:59")
    if request.args.get("q"):
        query += " AND raw_message LIKE ?"
        params.append(f"%{request.args.get('q')}%")
    query += " ORDER BY timestamp DESC LIMIT 300"

    rows = db.execute(query, params).fetchall()
    rows_html = ""
    for r in rows:
        row_class = "row-critical" if r["severity"] == "CRITICAL" else ""
        rows_html += f"""<tr class="{row_class}">
            <td>{r['timestamp']}</td><td>{r['source_ip'] or ''}</td><td>{r['destination_ip'] or '-'}</td>
            <td>{r['event_type'] or ''}</td>
            <td><span class="badge badge-{r['severity']}">{r['severity']}</span></td>
            <td><span class="badge badge-{r['alert_status']}">{r['alert_status']}</span></td>
            <td class="small text-secondary">{(r['raw_message'] or '')[:90]}</td>
            <td><a href="{url_for('log_detail', log_id=r['id'])}" class="btn small">View</a></td>
        </tr>"""
    if not rows_html:
        rows_html = '<tr><td colspan="8" class="text-secondary">No logs match the current filters.</td></tr>'

    body = body.replace(LOGS_ROWS_PLACEHOLDER, rows_html)
    return render_page("Logs", body, active="logs_page")


LOGS_ROWS_PLACEHOLDER = "___LOGS_ROWS___"


@app.route("/logs/<int:log_id>")
@login_required
def log_detail(log_id):
    db = get_db()
    row = db.execute("SELECT * FROM logs WHERE id = ?", (log_id,)).fetchone()
    if row is None:
        flash("Log entry not found.", "error")
        return redirect(url_for("logs_page"))

    body = f"""
    <div class="panel">
      <h2>Log Detail — #{row['id']}</h2>
      <table>
        <tr><th style="width:180px;">Timestamp</th><td>{row['timestamp']}</td></tr>
        <tr><th>Source IP</th><td>{row['source_ip'] or '-'}</td></tr>
        <tr><th>Destination IP</th><td>{row['destination_ip'] or '-'}</td></tr>
        <tr><th>Destination Port</th><td>{row['destination_port'] or '-'}</td></tr>
        <tr><th>Event Type</th><td>{row['event_type']}</td></tr>
        <tr><th>Severity</th><td><span class="badge badge-{row['severity']}">{row['severity']}</span></td></tr>
        <tr><th>Alert Status</th><td><span class="badge badge-{row['alert_status']}">{row['alert_status']}</span></td></tr>
        <tr><th>Raw Message</th><td>{row['raw_message']}</td></tr>
        <tr><th>Ingested At</th><td>{row['created_at']}</td></tr>
      </table>
      <div class="btn-row" style="margin-top:16px;">
        <a href="{url_for('logs_page')}" class="btn">← Back to Logs</a>
        <form method="POST" action="{url_for('delete_log', log_id=row['id'])}" onsubmit="return confirm('Delete this log entry?');">
          {csrf_input()}
          <button type="submit" class="btn btn-danger">🗑 Delete Log</button>
        </form>
      </div>
    </div>
    """
    return render_page(f"Log #{row['id']}", body, active="logs_page")


@app.route("/logs/<int:log_id>/delete", methods=["POST"])
@login_required
def delete_log(log_id):
    db = get_db()
    db.execute("DELETE FROM logs WHERE id = ?", (log_id,))
    db.commit()
    flash(f"Log #{log_id} deleted.", "success")
    return redirect(url_for("logs_page"))


@app.route("/logs/clear", methods=["POST"])
@login_required
def clear_logs():
    db = get_db()
    db.execute("DELETE FROM logs")
    db.commit()
    flash("All logs have been cleared.", "success")
    return redirect(url_for("logs_page"))


@app.route("/logs/export")
@login_required
def export_csv():
    db = get_db()
    rows = db.execute("SELECT * FROM logs ORDER BY timestamp DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "source_ip", "destination_ip", "destination_port",
                      "event_type", "severity", "raw_message", "alert_status", "created_at"])
    for r in rows:
        writer.writerow([r["id"], r["timestamp"], r["source_ip"], r["destination_ip"],
                          r["destination_port"], r["event_type"], r["severity"],
                          r["raw_message"], r["alert_status"], r["created_at"]])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_logs_export.csv"},
    )


# =====================================================================
# ROUTES: ALERTS PAGE
# =====================================================================

@app.route("/alerts")
@login_required
def alerts_page():
    db = get_db()
    severity_filter = request.args.get("severity", "")
    query = "SELECT * FROM logs WHERE alert_status = 'ALERT'"
    params = []
    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)
    query += """ ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2 ELSE 3 END, timestamp DESC LIMIT 300"""
    rows = db.execute(query, params).fetchall()

    options_html = '<option value="">All Severities</option>'
    for s in SEVERITY_LEVELS:
        sel = "selected" if severity_filter == s else ""
        options_html += f'<option value="{s}" {sel}>{s}</option>'

    rows_html = ""
    for r in rows:
        row_class = "row-critical" if r["severity"] == "CRITICAL" else ""
        rows_html += f"""<tr class="{row_class}">
            <td>{r['timestamp']}</td><td>{r['source_ip'] or ''}</td>
            <td>{r['event_type'] or ''}</td>
            <td><span class="badge badge-{r['severity']}">{r['severity']}</span></td>
            <td><span class="badge badge-{r['alert_status']}">{r['alert_status']}</span></td>
            <td class="small text-secondary">{(r['raw_message'] or '')[:100]}</td>
            <td><a href="{url_for('log_detail', log_id=r['id'])}" class="btn small">View</a></td>
        </tr>"""
    if not rows_html:
        rows_html = '<tr><td colspan="7" class="text-secondary">No active alerts.</td></tr>'

    body = f"""
    <div class="panel">
      <h2>Filter Alerts</h2>
      <form method="GET" action="{url_for('alerts_page')}" class="form-grid">
        <div><label>Severity</label><select name="severity" onchange="this.form.submit()">{options_html}</select></div>
      </form>
    </div>
    <div class="panel">
      <h2>Active Security Alerts (CRITICAL first)</h2>
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Time</th><th>Source IP</th><th>Event Type</th><th>Severity</th><th>Status</th><th>Message</th><th></th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
      </div>
    </div>
    """
    return render_page("Alerts", body, active="alerts_page")


# =====================================================================
# ROUTES: INGEST PAGE
# =====================================================================

@app.route("/ingest", methods=["GET", "POST"])
@login_required
def ingest_page():
    if request.method == "POST":
        form_type = request.form.get("form_type")

        if form_type == "manual":
            try:
                timestamp = request.form.get("timestamp") or datetime.datetime.utcnow().isoformat(timespec="seconds")
                source_ip = request.form.get("source_ip", "0.0.0.0").strip() or "0.0.0.0"
                destination_ip = request.form.get("destination_ip", "").strip() or None
                destination_port = request.form.get("destination_port", "").strip() or None
                event_type = request.form.get("event_type", "Generic Log Entry").strip() or "Generic Log Entry"
                severity = request.form.get("severity", "LOW").strip().upper()
                if severity not in SEVERITY_LEVELS:
                    severity = "LOW"
                raw_message = request.form.get("raw_message", "").strip() or "(no message provided)"

                insert_log({
                    "timestamp": timestamp, "source_ip": source_ip,
                    "destination_ip": destination_ip, "destination_port": destination_port,
                    "event_type": event_type, "severity": severity, "raw_message": raw_message,
                })
                run_alert_detection()
                flash("Log entry submitted successfully.", "success")
            except Exception:  # noqa: BLE001
                app.logger.exception("Manual log submission failed")
                flash("Failed to submit the log entry. Check the values and try again.", "error")

        elif form_type == "upload":
            file = request.files.get("logfile")
            if not file or file.filename == "":
                flash("No file selected.", "error")
            else:
                try:
                    raw_bytes = file.read()
                    try:
                        text = raw_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        text = raw_bytes.decode("latin-1", errors="replace")

                    lines = text.splitlines()
                    inserted, failed = 0, 0
                    for line in lines:
                        try:
                            parsed = parse_log_line(line)
                            if parsed is not None:
                                insert_log(parsed)
                                inserted += 1
                        except Exception:  # noqa: BLE001
                            failed += 1
                            continue
                    run_alert_detection()
                    flash(f"Uploaded '{file.filename}': {inserted} log lines ingested"
                          + (f", {failed} lines failed safely." if failed else "."), "success")
                except Exception:  # noqa: BLE001
                    app.logger.exception("Log file ingestion failed")
                    flash("Failed to process the uploaded file. Check the file and try again.", "error")

        return redirect(url_for("ingest_page"))

    event_options = "".join(f'<option value="{e}">{e}</option>' for e in sorted(SUSPICIOUS_EVENT_TYPES | {"Successful SSH Login", "Generic Log Entry"}))
    severity_options = "".join(f'<option value="{s}">{s}</option>' for s in SEVERITY_LEVELS)

    body = f"""
    <div class="panel">
      <h2>1. Manual Log Submission</h2>
      <form method="POST" action="{url_for('ingest_page')}">
        <input type="hidden" name="form_type" value="manual">
        {csrf_input()}
        <div class="form-grid">
          <div><label>Timestamp (ISO, optional)</label><input type="text" name="timestamp" placeholder="2026-09-01T12:00:00"></div>
          <div><label>Source IP</label><input type="text" name="source_ip" placeholder="192.168.1.10" required></div>
          <div><label>Destination IP</label><input type="text" name="destination_ip" placeholder="10.0.0.5"></div>
          <div><label>Destination Port</label><input type="text" name="destination_port" placeholder="22"></div>
          <div><label>Event Type</label><select name="event_type">{event_options}</select></div>
          <div><label>Severity</label><select name="severity">{severity_options}</select></div>
        </div>
        <label>Raw Message</label>
        <textarea name="raw_message" rows="3" class="mb-16" placeholder="Failed password for invalid user admin from 192.168.1.10 port 51422 ssh2"></textarea>
        <button type="submit" class="btn btn-primary">Submit Log Entry</button>
      </form>
    </div>

    <div class="panel">
      <h2>2. Upload Log File</h2>
      <p class="text-secondary small mb-16">Accepted formats: .txt, .log, .csv — one log entry per line. Malformed lines are stored safely with default values and will never crash the app.</p>
      <form method="POST" action="{url_for('ingest_page')}" enctype="multipart/form-data">
        <input type="hidden" name="form_type" value="upload">
        {csrf_input()}
        <input type="file" name="logfile" accept=".txt,.log,.csv" class="mb-16" required>
        <button type="submit" class="btn btn-primary">Upload &amp; Ingest</button>
      </form>
    </div>

    <div class="panel">
      <h2>3. Generate Sample Security Logs</h2>
      <p class="text-secondary small mb-16">Automatically generates realistic synthetic cybersecurity lab events (failed logins, port scans, malware detections, brute force attempts, C2 beacons, IDS/Suricata alerts, etc.) using private lab IP ranges only.</p>
      <form method="POST" action="{url_for('generate_sample')}">
        {csrf_input()}
        <button type="submit" class="btn btn-primary">⚡ Generate Sample Security Logs</button>
      </form>
    </div>
    """
    return render_page("Ingest Logs", body, active="ingest_page")


# =====================================================================
# ROUTES: SETTINGS PAGE
# =====================================================================

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    if request.method == "POST":
        try:
            threshold = int(request.form.get("threshold", DEFAULT_THRESHOLD))
            time_window = int(request.form.get("time_window_min", DEFAULT_TIME_WINDOW_MIN))
            refresh_interval = int(request.form.get("refresh_interval", DEFAULT_REFRESH_INTERVAL))
            threshold = max(1, threshold)
            time_window = max(1, time_window)
            refresh_interval = max(5, refresh_interval)

            set_setting("threshold", threshold)
            set_setting("time_window_min", time_window)
            set_setting("refresh_interval", refresh_interval)
            run_alert_detection()
            flash("Settings updated successfully.", "success")
        except Exception:  # noqa: BLE001
            app.logger.exception("Settings update failed")
            flash("Failed to update settings. Check the values and try again.", "error")
        return redirect(url_for("settings_page"))

    threshold = get_setting("threshold", DEFAULT_THRESHOLD)
    time_window = get_setting("time_window_min", DEFAULT_TIME_WINDOW_MIN)
    refresh_interval = get_setting("refresh_interval", DEFAULT_REFRESH_INTERVAL)

    body = f"""
    <div class="panel">
      <h2>Detection &amp; Refresh Settings</h2>
      <form method="POST" action="{url_for('settings_page')}" class="form-grid">
        {csrf_input()}
        <div>
          <label>Suspicious Event Threshold</label>
          <input type="number" name="threshold" min="1" value="{threshold}">
        </div>
        <div>
          <label>Detection Time Window (minutes)</label>
          <input type="number" name="time_window_min" min="1" value="{time_window}">
        </div>
        <div>
          <label>Auto-Refresh Interval (seconds)</label>
          <input type="number" name="refresh_interval" min="5" value="{refresh_interval}">
        </div>
      </form>
      <button type="submit" form="" class="btn btn-primary" onclick="this.closest('.panel').querySelector('form').submit()">Save Settings</button>
      <p class="text-secondary small" style="margin-top:14px;">
        Defaults: threshold = {DEFAULT_THRESHOLD} suspicious events within {DEFAULT_TIME_WINDOW_MIN} minutes.
        These settings drive brute-force, port-scan, and repeated-suspicious-activity detection across the whole application.
      </p>
    </div>
    """
    return render_page("Settings", body, active="settings_page")


# =====================================================================
# ROUTES: ABOUT PAGE
# =====================================================================

@app.route("/about")
@login_required
def about_page():
    body = """
    <div class="panel">
      <h2>About SOC Dashboard — Mini SIEM</h2>
      <p class="mb-16">This project demonstrates, at a beginner-friendly level, how a simplified
      Security Information and Event Management (SIEM) system works internally. It was built as a
      cybersecurity internship capstone project.</p>
      <p class="mb-16">The application demonstrates the following core SOC/SIEM concepts:</p>
      <ul style="margin-left:20px; margin-bottom:16px; line-height:1.9;">
        <li>Log ingestion (manual entry, file upload, and synthetic sample generation)</li>
        <li>Log normalization into a consistent schema</li>
        <li>Persistent storage using a SQLite database</li>
        <li>Configurable threshold-based security event detection</li>
        <li>Alert visualization with charts and severity-coded tables</li>
        <li>Basic SOC analyst investigation workflows (search, filter, drill-down)</li>
      </ul>
    </div>
    <div class="panel">
      <div class="alert-banner" style="margin-bottom:0;">
        <strong>This application is designed strictly for authorized isolated lab environments and synthetic
        security data. It must not be used to monitor systems or networks without explicit authorization.</strong>
      </div>
    </div>
    """
    return render_page("About", body, active="about_page")


# =====================================================================
# API ENDPOINTS
# =====================================================================

@app.route("/api/dashboard")
@login_required
def api_dashboard():
    db = get_db()
    total_logs = db.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    total_alerts = db.execute("SELECT COUNT(*) c FROM logs WHERE alert_status='ALERT'").fetchone()["c"]
    critical_alerts = db.execute("SELECT COUNT(*) c FROM logs WHERE severity='CRITICAL'").fetchone()["c"]
    high_alerts = db.execute("SELECT COUNT(*) c FROM logs WHERE severity='HIGH'").fetchone()["c"]
    unique_ips = db.execute("SELECT COUNT(DISTINCT source_ip) c FROM logs").fetchone()["c"]

    recent = db.execute(
        """SELECT * FROM logs ORDER BY
           CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
           timestamp DESC LIMIT 15"""
    ).fetchall()

    event_dist = db.execute(
        "SELECT event_type, COUNT(*) as count FROM logs GROUP BY event_type ORDER BY count DESC LIMIT 10"
    ).fetchall()

    return jsonify({
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "unique_ips": unique_ips,
        "recent_alerts": [dict(r) for r in recent],
        "event_type_distribution": [dict(r) for r in event_dist],
    })


@app.route("/api/logs")
@login_required
def api_logs():
    db = get_db()
    rows = db.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/alerts")
@login_required
def api_alerts():
    db = get_db()
    rows = db.execute(
        """SELECT * FROM logs WHERE alert_status='ALERT' ORDER BY
           CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
           timestamp DESC LIMIT 200"""
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/top-offenders")
@login_required
def api_top_offenders():
    db = get_db()
    rows = db.execute(
        """SELECT source_ip,
                  COUNT(*) as count,
                  MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) as sev_rank
           FROM logs WHERE source_ip IS NOT NULL
           GROUP BY source_ip ORDER BY count DESC LIMIT 10"""
    ).fetchall()
    sev_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
    result = [
        {"source_ip": r["source_ip"], "count": r["count"], "max_severity": sev_map.get(r["sev_rank"], "LOW")}
        for r in rows
    ]
    return jsonify(result)


@app.route("/api/timeline")
@login_required
def api_timeline():
    db = get_db()
    rows = db.execute(
        """SELECT substr(timestamp, 1, 13) as hour_bucket, COUNT(*) as count
           FROM logs GROUP BY hour_bucket ORDER BY hour_bucket ASC LIMIT 48"""
    ).fetchall()
    labels = [r["hour_bucket"] + ":00" for r in rows]
    counts = [r["count"] for r in rows]
    return jsonify({"labels": labels, "counts": counts})


@app.route("/api/severity")
@login_required
def api_severity():
    db = get_db()
    counts = []
    for sev in SEVERITY_LEVELS:
        c = db.execute("SELECT COUNT(*) c FROM logs WHERE severity = ?", (sev,)).fetchone()["c"]
        counts.append(c)
    return jsonify({"labels": SEVERITY_LEVELS, "counts": counts})


# =====================================================================
# ERROR HANDLERS
# =====================================================================

@app.errorhandler(404)
def not_found(e):
    body = '<div class="panel"><h2>404 — Page Not Found</h2><p class="text-secondary">The page you requested does not exist.</p></div>'
    if "user_id" in session:
        return render_page("Not Found", body), 404
    return redirect(url_for("login"))


@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Unhandled server error: %s", e)
    body = '<div class="panel"><h2>500 — Internal Server Error</h2><p class="text-secondary">An unexpected error occurred. The details were written to the server log.</p></div>'
    if "user_id" in session:
        return render_page("Error", body), 500
    return redirect(url_for("login"))


# =====================================================================
# ENTRY POINT
# =====================================================================

if __name__ == "__main__":
    init_db()
    host = os.environ.get("SOC_HOST", "127.0.0.1")
    port = int(os.environ.get("SOC_PORT", "5000"))
    # Debug mode exposes the Werkzeug console, which is remote code execution if
    # the port is ever reachable. It is opt-in, and never the default.
    debug = os.environ.get("SOC_DEBUG") == "1"
    print("=" * 70)
    print(" SOC Dashboard — Mini SIEM (Lab Edition)")
    print(" Database: " + DATABASE)
    print(f" URL: http://{host}:{port}")
    if debug:
        print(" DEBUG MODE ENABLED — do not expose this port")
    print("=" * 70)
    app.run(host=host, port=port, debug=debug)
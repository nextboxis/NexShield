import os
import io
import csv
import ipaddress
import json
import uuid
import re
import secrets
import logging
import threading
import time as _time
from collections import defaultdict
from typing import Any  # type: ignore
import requests # type: ignore
from msf_utils import map_threat_to_module, generate_rc_script, EXPLOIT_DATABASE, MSF_MAPPINGS
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, make_response # type: ignore
from flask_cors import CORS # type: ignore
from flask_socketio import SocketIO, emit # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from functools import wraps
from datetime import datetime, timezone, timedelta, date

# Optional BSON support (only available with MongoDB/pymongo)
try:
    from bson import ObjectId, json_util  # type: ignore
    _HAS_BSON = True
except ImportError:
    _HAS_BSON = False

# Internal Logic Modules
from ai_logic import compute_risk_scores # type: ignore
from config import threats, network_scans, activity_log, users, cve_cache, ip_geo_cache, scan_jobs, check_connection # type: ignore

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "nexshield-local-secret-12345")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

_ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000"
).split(",")
socketio = SocketIO(app, cors_allowed_origins=_ALLOWED_ORIGINS)

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
ALLOWED_EXPORT_FORMATS = {"csv", "json"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TARGET_RE = re.compile(r"^[A-Za-z0-9.,:/\-\s]+$")
PORTS_RE = re.compile(r"^[0-9,\-\s]*$")


# ═════════════════════════════════════════════════════════════════════
#  Utility & Logging
# ═════════════════════════════════════════════════════════════════════

def _serialize(doc):
    """
    Standardizes document serialization for JSON-safe API delivery.
    Handles BSON types (ObjectId, datetime) when using MongoDB,
    or plain dict/list serialization when using TinyDB.
    """
    if _HAS_BSON:
        return json.loads(json_util.dumps(doc))

    # TinyDB fallback: manual serialization
    def _convert(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        if isinstance(obj, dict):
            return {k: _convert(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_convert(i) for i in obj]
        return obj

    if isinstance(doc, (list, tuple)):
        return [_convert(d) for d in doc]
    if isinstance(doc, dict):
        return _convert(doc)
    return doc


def _log_activity(event_type, message, severity="info"):
    """
    Centralized logging utility for the NexShield Activity Log.
    Ensures systemic events are persisted for the "Mission Control" console.
    """
    try:
        if check_connection():
            activity_log.insert_one({
                "type": event_type,
                "message": message,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc),
            })
    except Exception as e:
        logger.error("Activity logging failed: %s", e)


def _normalize_limit(value: int | None, default: int, maximum: int) -> int:
    if value is None:
        return default
    return max(1, min(value, maximum))


def _validate_username(username):
    candidate = (username or "").strip()
    if not USERNAME_RE.fullmatch(candidate):
        raise ValueError("Username must be 3-32 characters and use only letters, numbers, ., _, or -.")
    return candidate


def _validate_scan_inputs(target: str | None, ports: str | None, default_ports: str = "") -> tuple[str, str]:
    clean_target = (target or "").strip()
    clean_ports = (ports or "").strip()

    if not clean_target:
        raise ValueError("A scan target is required.")
    if len(clean_target) > 120 or not TARGET_RE.fullmatch(clean_target):
        raise ValueError("Scan target contains unsupported characters.")

    if not clean_ports:
        clean_ports = default_ports.strip()

    if clean_ports:
        if len(clean_ports) > 120 or not PORTS_RE.fullmatch(clean_ports):
            raise ValueError("Port list must contain only digits, commas, spaces, or hyphens.")

        for part in [segment.strip() for segment in clean_ports.split(",") if segment.strip()]:
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                if not start_str.isdigit() or not end_str.isdigit():
                    raise ValueError("Port ranges must be numeric.")
                start_port = int(start_str)
                end_port = int(end_str)
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError("Port ranges must stay within 1-65535.")
            else:
                if not part.isdigit():
                    raise ValueError("Port values must be numeric.")
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError("Port values must stay within 1-65535.")

    return clean_target, clean_ports


def _validate_cve_id(cve_id):
    candidate = (cve_id or "").strip().upper()
    if not CVE_RE.fullmatch(candidate):
        raise ValueError("Invalid CVE identifier. Use the format CVE-YYYY-NNNN.")
    return candidate


def _start_background_task(target, *args):
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    return thread


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' cdnjs.cloudflare.com cdn.socket.io cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdnjs.cloudflare.com cdn.jsdelivr.net; "
        "font-src 'self' fonts.gstatic.com cdnjs.cloudflare.com; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:;"
    )
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# No global CORS needed if running on same origin/proxy


# ═════════════════════════════════════════════════════════════════════
#  Authentication Helpers
# ═════════════════════════════════════════════════════════════════════

def login_required(f):
    """Decorator: rejects unauthenticated requests with HTTP 401."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"status": "error", "message": "Authentication required."}), 401
        return f(*args, **kwargs)
    return decorated


DEFAULT_DASHBOARD_PATH = "/dashboard"


def _safe_next_path(next_path: str | None, fallback: str = DEFAULT_DASHBOARD_PATH) -> str:
    """Allow only local, non-login return paths after authentication."""
    candidate = (next_path or "").strip()
    if not candidate:
        return fallback
    
    from urllib.parse import urlparse
    parsed = urlparse(candidate)
    
    # Must not have a netloc or scheme (must be a relative path)
    if parsed.netloc or parsed.scheme:
        return fallback
    
    # Must start with a slash
    if not parsed.path.startswith("/"):
        return fallback
        
    if parsed.path == "/login":
        return fallback
        
    return candidate


def _validate_host(host_str: str | None) -> str:
    """Validate and sanitize a host IP or hostname."""
    candidate = (host_str or "").strip()
    if not candidate:
        raise ValueError("Host is required.")
    if len(candidate) > 120:
        raise ValueError("Host value too long.")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    try:
        ipaddress.ip_network(candidate, strict=False)
        return candidate
    except ValueError:
        pass
    if TARGET_RE.fullmatch(candidate):
        return candidate
    raise ValueError("Invalid host format.")


# ── In-memory rate limiter ───────────────────────────────────────────
_rate_limit_store: dict[str, list[float]] = defaultdict(list)

_rate_limit_call_count: int = 0

def _rate_limit(key: str, max_requests: int = 10, window_sec: int = 60) -> bool:
    """Returns True if rate limit is exceeded."""
    global _rate_limit_call_count
    now = _time.time()
    _rate_limit_store[key] = [t for t in _rate_limit_store[key] if now - t < window_sec]

    # Periodic cleanup: every 100 calls, purge stale keys across all entries
    _rate_limit_call_count += 1
    if _rate_limit_call_count >= 100:
        _rate_limit_call_count = 0
        stale_keys = [
            k for k, timestamps in _rate_limit_store.items()
            if not timestamps or all(now - t >= window_sec for t in timestamps)
        ]
        for k in stale_keys:
            del _rate_limit_store[k]

    if len(_rate_limit_store[key]) >= max_requests:
        return True
    _rate_limit_store[key].append(now)
    return False


# ═════════════════════════════════════════════════════════════════════
#  Security / Authentication
# ═════════════════════════════════════════════════════════════════════

# Generate a secure random token for this server session
WS_TOKEN = os.environ.get("WS_TOKEN", secrets.token_hex(16))

@app.route("/api/auth/token", methods=["GET"])
@login_required
def get_ws_token():
    """Returns the WebSocket authorization token. Requires authentication."""
    return jsonify({"status": "complete", "token": WS_TOKEN})

@socketio.on("connect")
def handle_connect(auth):
    """Secure the WebSocket connection by validating the auth token."""
    if not auth or auth.get("token") != WS_TOKEN:
        _log_activity("security", f"Blocked unauthorized WebSocket connection (IP: {request.remote_addr})", "high")
        raise ConnectionRefusedError("Unauthorized: Invalid or missing token")
    # Connection accepted

# ═════════════════════════════════════════════════════════════════════
#  API — User Registration / Login / Logout
# ═════════════════════════════════════════════════════════════════════

PASSWORD_RE = re.compile(r"^.{5,128}$")  # Minimum 5 characters

@app.route("/api/auth/register", methods=["POST"])
def register():
    """Registration disabled — local-only tool. Admin account is auto-provisioned."""
    return jsonify({"status": "error", "message": "Registration is disabled. This is a local-only tool. Use the default admin account."}), 403


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate and create a session."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database offline."}), 503

    ip_key = f"login:{request.remote_addr}"
    if _rate_limit(ip_key, max_requests=10, window_sec=60):
        _log_activity("security", f"Rate-limited login attempts from {request.remote_addr}", "high")
        return jsonify({"status": "error", "message": "Too many login attempts. Try again later."}), 429

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required."}), 400

    user_doc = users.find_one({"username": username})
    if not user_doc:
        # Case-insensitive fallback
        user_doc = users.find_one({"username": {"$regex": f"^{re.escape(username)}$", "$options": "i"}})
    if not user_doc or not check_password_hash(user_doc["password_hash"], password):
        _log_activity("security", f"Failed login attempt for '{username}' from {request.remote_addr}", "warning")
        return jsonify({"status": "error", "message": "Invalid credentials."}), 401

    canonical_username = user_doc.get("username", username)
    session.clear()
    session.permanent = True
    session["user"] = canonical_username
    session["role"] = user_doc.get("role", "analyst")
    _log_activity("auth", f"User '{canonical_username}' logged in from {request.remote_addr}")
    return jsonify({
        "status": "complete",
        "message": f"Welcome, {canonical_username}.",
        "user": canonical_username,
        "role": session["role"],
        "redirect": _safe_next_path(body.get("next")),
    })


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    """End the current session."""
    username = session.pop("user", "unknown")
    session.clear()
    _log_activity("auth", f"User '{username}' logged out")
    return jsonify({"status": "complete", "message": "Logged out."})


@app.route("/api/auth/session", methods=["GET"])
def check_session():
    """Check if the current session is authenticated."""
    if "user" in session:
        return jsonify({"status": "complete", "authenticated": True, "user": session["user"], "role": session.get("role", "analyst")})
    return jsonify({"status": "complete", "authenticated": False})


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def change_password():
    """Change password for the currently authenticated user."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database offline."}), 503

    body = request.get_json(silent=True) or {}
    current_pw = (body.get("current_password") or "").strip()
    new_pw = (body.get("new_password") or "").strip()
    confirm_pw = (body.get("confirm_password") or "").strip()

    if not current_pw or not new_pw or not confirm_pw:
        return jsonify({"status": "error", "message": "All password fields are required."}), 400
    if new_pw != confirm_pw:
        return jsonify({"status": "error", "message": "New passwords do not match."}), 400
    if len(new_pw) < 5:
        return jsonify({"status": "error", "message": "New password must be at least 5 characters."}), 400
    if new_pw == current_pw:
        return jsonify({"status": "error", "message": "New password must differ from current password."}), 400

    username = session.get("user")
    user_doc = users.find_one({"username": username})
    if not user_doc or not check_password_hash(user_doc["password_hash"], current_pw):
        return jsonify({"status": "error", "message": "Current password is incorrect."}), 401

    users.update_one(
        {"username": username},
        {"$set": {"password_hash": generate_password_hash(new_pw)}}
    )
    _log_activity("auth", f"Password changed for user '{username}'")
    return jsonify({"status": "complete", "message": "Password updated successfully."})


@app.route("/api/auth/profile", methods=["GET"])
@login_required
def get_profile():
    """Get profile info for the currently authenticated user."""
    username = session.get("user")
    role = session.get("role", "analyst")
    return jsonify({
        "status": "complete",
        "username": username,
        "role": role,
    })


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring."""
    db_ok = check_connection()
    return jsonify({
        "status": "healthy" if db_ok else "degraded",
        "database": "online" if db_ok else "offline",
        "version": "6.0",
    }), 200 if db_ok else 503


# ═════════════════════════════════════════════════════════════════════
#  Frontend
# ═════════════════════════════════════════════════════════════════════

@app.route("/")
def root_redirect():
    """Send users to the right frontend entry point for their session state."""
    session.clear()
    return redirect(url_for("serve_login", next=DEFAULT_DASHBOARD_PATH))


@app.route("/login")
def serve_login():
    """Serve the authentication page. Always accessible."""
    session.clear()
    return render_template("login.html")


@app.route("/dashboard")
def serve_dashboard():
    """Serve the NexShield Mission Control dashboard. Requires login."""
    if "user" not in session:
        return redirect(url_for("serve_login", next=DEFAULT_DASHBOARD_PATH))
    return render_template("index.html")


@app.route("/report")
def serve_report():
    """Serve the formatted HTML penetration testing report page. Requires login."""
    if "user" not in session:
        return redirect(url_for("serve_login", next="/report"))
    return render_template("report.html")





# ═════════════════════════════════════════════════════════════════════
#  API — Seed Data (Bootstrap AI)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/seed-data", methods=["POST"])
def seed_data():
    """Synthetic seed data is disabled; only live scan data is accepted."""
    return jsonify({
        "status": "error",
        "message": "Synthetic seed data has been disabled. Use a real-time scan target instead.",
    }), 410


@app.route("/api/reset-data", methods=["POST"])
@login_required
def reset_data():
    """Clear operational data while preserving user accounts. Requires authentication."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database offline."}), 503

    body = request.get_json(silent=True) or {}
    include_cache = bool(body.get("include_cache", False))

    deleted = {
        "threats": threats.delete_many({}).deleted_count,
        "network_scans": network_scans.delete_many({}).deleted_count,
        "activity_log": activity_log.delete_many({}).deleted_count,
        "cve_cache": 0,
    }

    if include_cache:
        deleted["cve_cache"] = cve_cache.delete_many({}).deleted_count  # type: ignore

    cleared_total = sum(deleted.values())
    cache_note = " including CVE cache" if include_cache else ""
    message = f"Reset complete. Removed {cleared_total} old records{cache_note}."

    current_user = session.get("user", "unknown")
    _log_activity("system", f"Operational data reset by '{current_user}'", "high")
    socketio.emit("data_reset", {"status": "success", "message": message, "deleted": deleted})

    return jsonify({
        "status": "complete",
        "message": message,
        "deleted": deleted,
    })




# ═════════════════════════════════════════════════════════════════════
#  API — Threats
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/threats", methods=["GET"])
@login_required
def get_threats():
    """Return the latest 10 threats, sorted by detection time (descending)."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable", "threats": []}), 503

    limit = _normalize_limit(request.args.get("limit", 10, type=int), 10, 100)

    docs = list(
        threats.find()
        .sort("detected_at", -1)
        .limit(limit)
    )
    
    # Enrich with weaponization metadata
    enriched = []
    for t in docs:
        t_serialized = _serialize(t)
        name = str(t.get("name") or "").lower()
        detail = str(t.get("detail") or "").lower()
        cve = str(t.get("cve_id") or "").lower()
        
        t_serialized["exploit_module"] = map_threat_to_module(t)
        enriched.append(t_serialized)

    return jsonify({"status": "complete", "threats": enriched})


# ═════════════════════════════════════════════════════════════════════
#  API — Active Response (Zero-Trust)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/quarantine", methods=["POST"])
@login_required
def quarantine_host():
    """Simulate a network-level quarantine and remediate threats. Requires authentication."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    body = request.get_json(silent=True) or {}
    try:
        host = _validate_host(body.get("host"))
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    # Quarantine logic: Update all active threats for this host
    result = threats.update_many(
        {"host": host, "severity": {"$ne": "low"}},
        {"$set": {
            "severity": "low",
            "detail": "[QUARANTINED] Network access restricted. "
        }}
    )

    if result.modified_count > 0:
        current_user = session.get("user", "unknown")
        _log_activity("security", f"Host {host} quarantined by {current_user}", "critical")
        
        # Trigger risk score recalculation
        try:
            from ai_logic import compute_risk_scores # type: ignore
            compute_risk_scores()
        except Exception as e:
            logger.warning("Risk recalculation failed post-quarantine: %s", e)

        # Broadcast update
        socketio.emit("quarantine_complete", {
            "status": "success",
            "message": f"Host {host} successfully isolated.",
            "host": host
        })

        return jsonify({
            "status": "complete",
            "message": f"Isolated {host} and neutralized {result.modified_count} threats."
        })
    else:
        return jsonify({
            "status": "info",
            "message": f"Host {host} has no active threats to quarantine."
        })

# ═════════════════════════════════════════════════════════════════════
#  API — Target Node Profiling
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/host/<path:ip>", methods=["GET"])
@login_required
def get_host_profile(ip):
    """Retrieve deep scan results (footprint) for a particular IP."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    ip = ip.strip()
    
    # Retrieve the latest scan footprint for this host
    scan_doc = network_scans.find_one(
        {"host": ip},
        sort=[("scanned_at", -1)]
    )
    
    return jsonify({
        "status": "complete",
        "host": ip,
        "footprint": _serialize(scan_doc) if scan_doc else None
    })

@app.route("/api/export-scan", methods=["GET"])
@login_required
def export_scan():
    """Export the raw JSON scan footprint for a particular IP."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    ip = (request.args.get("host") or "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "Target IP required."}), 400

    scan_doc = network_scans.find_one(
        {"host": ip},
        sort=[("scanned_at", -1)]
    )

    if not scan_doc:
        return jsonify({"status": "error", "message": "No scan records found for this host."}), 404

    safe_doc = _serialize(scan_doc)
    json_data = json.dumps(safe_doc, indent=2)

    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=scan_footprint_{ip.replace('.','_')}.json"}
    )

# ═════════════════════════════════════════════════════════════════════
#  API — Stats
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    """Return aggregate counts: total threats, scans, severity breakdown."""
    if not check_connection():
        return jsonify({
            "status": "error",
            "message": "Database unavailable",
            "db_online": False,
            "total_threats": 0, "total_scans": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        }), 503

    total_threats = threats.count_documents({})
    total_scans = network_scans.count_documents({})
    critical = threats.count_documents({"severity": "critical"})
    high = threats.count_documents({"severity": "high"})
    medium = threats.count_documents({"severity": "medium"})
    low = threats.count_documents({"severity": "low"})

    return jsonify({
        "status": "complete",
        "db_online": True,
        "total_threats": total_threats,
        "total_scans": total_scans,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    })


@app.route("/api/dashboard/summary", methods=["GET"])
@login_required
def dashboard_summary():
    """Combined dashboard data: stats + recent threats + activity. Reduces multiple API calls to one."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    # Stats
    total_threats = threats.count_documents({})
    total_scans = network_scans.count_documents({})
    critical = threats.count_documents({"severity": "critical"})
    high = threats.count_documents({"severity": "high"})
    medium = threats.count_documents({"severity": "medium"})
    low = threats.count_documents({"severity": "low"})

    # Recent threats
    recent_threats = list(threats.find().sort("detected_at", -1).limit(10))
    enriched = []
    for t in recent_threats:
        t_ser = _serialize(t)
        t_ser["exploit_module"] = map_threat_to_module(t)
        enriched.append(t_ser)

    # Recent activity
    recent_activity = list(activity_log.find().sort("timestamp", -1).limit(20))

    return jsonify({
        "status": "complete",
        "stats": {
            "total_threats": total_threats,
            "total_scans": total_scans,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "db_online": True,
        },
        "recent_threats": enriched,
        "recent_activity": _serialize(recent_activity),
    })


# ═════════════════════════════════════════════════════════════════════
#  API — Severity Timeline (last 7 days)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/timeline", methods=["GET"])
@login_required
def get_timeline():
    """Return threat counts per day per severity for the last 7 days."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    days = _normalize_limit(request.args.get("days", 7, type=int), 7, 30)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    docs = threats.find({"detected_at": {"$gte": cutoff}})

    timeline = {}
    for doc in docs:
        dt_val = doc.get("detected_at")
        if not dt_val:
            continue

        if isinstance(dt_val, str):
            try:
                # Replace 'Z' with '+00:00' to ensure fromisoformat works on older Python
                dt_str = dt_val.replace('Z', '+00:00')
                dt = datetime.fromisoformat(dt_str)
                day = dt.strftime("%Y-%m-%d")
            except ValueError:
                continue
        elif isinstance(dt_val, datetime):
            day = dt_val.strftime("%Y-%m-%d")
        else:
            continue

        sev = doc.get("severity")
        if day not in timeline:
            timeline[day] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        if sev in timeline[day]:
            timeline[day][sev] += 1

    # Fill in missing days with zeros
    all_days = []
    for i in range(days):
        d = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        all_days.append(d)
        if d not in timeline:
            timeline[d] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    return jsonify({
        "status": "complete",
        "days": all_days,
        "timeline": timeline,
    })


# ═════════════════════════════════════════════════════════════════════
#  API — Scan trigger (Enhanced with scan types, nmap lock, progress)
# ═════════════════════════════════════════════════════════════════════

ALLOWED_SCAN_TYPES = {"quick", "default", "deep", "stealth", "udp", "vuln", "os", "ssl", "full"}

@app.route("/api/scan", methods=["POST"])
@login_required
def trigger_scan():
    """Trigger a network scan. Accepts JSON: {target, ports, scan_type}. Requires authentication."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database is offline. Please start MongoDB."}), 503

    def background_scan(tgt, prts, stype):
        try:
            def on_progress(pct, msg):
                socketio.emit("scan_progress", {"percent": pct, "message": msg, "target": tgt})

            _log_activity("scan_start", f"[{stype.upper()}] Scan initiated on {tgt} (ports: {prts})")
            results = run_scan(tgt, prts, scan_type=stype, progress_callback=on_progress)
            msg = f"Scan complete: {len(results)} host(s) found on {tgt} [{stype}]"
            _log_activity("scan_complete", msg, "success")
            socketio.emit("scan_complete", {"status": "success", "message": msg, "host_count": len(results)})
        except RuntimeError as err:
            msg = f"Scan blocked: {str(err)}"
            _log_activity("scan_error", msg, "error")
            socketio.emit("scan_complete", {"status": "error", "message": msg})
        except Exception as err:
            msg = f"Scan failed: {str(err)}"
            _log_activity("scan_error", msg, "error")
            socketio.emit("scan_complete", {"status": "error", "message": msg})

    try:
        from scanner import run_scan, DEFAULT_PORTS, SCAN_TYPES, is_scan_running, validate_target  # type: ignore

        # Check nmap lock — prevent concurrent scans
        if is_scan_running():
            return jsonify({
                "status": "error",
                "message": "A scan is already running. Wait for it to finish.",
            }), 409

        body = request.get_json(silent=True) or {}
        target, ports = _validate_scan_inputs(
            body.get("target"),
            body.get("ports"),
            DEFAULT_PORTS,
        )

        # Validate scan type
        scan_type = (body.get("scan_type") or "default").strip().lower()
        if scan_type not in ALLOWED_SCAN_TYPES:
            return jsonify({"status": "error", "message": f"Invalid scan type. Use: {', '.join(sorted(ALLOWED_SCAN_TYPES))}"}), 400

        # Deep target validation via scanner module
        tv = validate_target(target)
        if not tv["valid"]:
            return jsonify({"status": "error", "message": tv["error"]}), 400

        scan_label = SCAN_TYPES.get(scan_type, {}).get("label", scan_type)

        # Run scan in the background to prevent HTTP timeout
        _start_background_task(background_scan, target, ports, scan_type)

        return jsonify({
            "status": "accepted",
            "message": f"{scan_label} started on {target}. Check activity logs for progress.",
            "target": target,
            "scan_type": scan_type,
            "target_info": tv,
        }), 202
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as e:
        _log_activity("scan_error", f"Scan failed: {str(e)}", "error")
        logger.error("Scan trigger error: %s", e)
        return jsonify({"status": "error", "message": "An internal error occurred. Check server logs."}), 500


@app.route("/api/scan/status", methods=["GET"])
@login_required
def scan_status():
    """Check if a scan is currently running and its progress."""
    try:
        from scanner import get_scan_status  # type: ignore
        return jsonify({"status": "complete", **get_scan_status()})
    except Exception as e:
        logger.error("Scan status check error: %s", e)
        return jsonify({"status": "error", "message": "An internal error occurred."}), 500


@app.route("/api/scan/nmap-check", methods=["GET"])
@login_required
def nmap_check():
    """Verify nmap is installed and return version/path info."""
    try:
        from scanner import check_nmap_installed, SCAN_TYPES  # type: ignore
        ok, info = check_nmap_installed()
        return jsonify({
            "status": "complete",
            "nmap_ok": ok,
            "nmap_info": info,
            "scan_types": {k: v["label"] for k, v in SCAN_TYPES.items()},
        })
    except Exception:
        logger.exception("Nmap check error")
        return jsonify({"status": "error", "message": "An internal error occurred."}), 500


@app.route("/api/hosts", methods=["GET"])
@login_required
def list_hosts():
    """Return all discovered hosts with aggregated stats."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    pipeline = [
        {"$group": {
            "_id": "$host",
            "hostname": {"$first": "$hostname"},
            "scan_count": {"$sum": 1},
            "latest_scan": {"$max": "$scanned_at"},
            "first_seen": {"$min": "$scanned_at"},
            "scan_types": {"$addToSet": "$scan_type"},
            "os_name": {"$first": "$os_detection.name"},
            "open_ports": {"$max": "$open_port_count"},
            "services": {"$first": "$services_detected"},
        }},
        {"$sort": {"latest_scan": -1}},
        {"$limit": 200},
    ]

    hosts = list(network_scans.aggregate(pipeline))
    result = []
    for h in hosts:
        ip = h["_id"]
        if not ip:
            continue
        # Get threat count for this host
        threat_count = threats.count_documents({"host": ip})
        result.append({
            "host": ip,
            "hostname": h.get("hostname", ""),
            "scan_count": h.get("scan_count", 0),
            "latest_scan": _serialize(h.get("latest_scan")),
            "first_seen": _serialize(h.get("first_seen")),
            "os_name": h.get("os_name", ""),
            "open_ports": h.get("open_ports", 0),
            "services": h.get("services", []),
            "threat_count": threat_count,
        })

    return jsonify({"status": "complete", "hosts": result, "total": len(result)})


@app.route("/api/topology", methods=["GET"])
@login_required
def network_topology():
    """Return 2D network topology graph nodes and links for discovered hosts."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    scans = list(network_scans.find().sort("scanned_at", -1).limit(200))
    nodes = []
    links = []
    seen_nodes = set()
    subnets = defaultdict(list)

    for scan in scans:
        host = scan.get("host")
        if not host or host in seen_nodes:
            continue
        seen_nodes.add(host)

        try:
            ip_obj = ipaddress.ip_address(host)
            subnet_str = f"{str(ip_obj).rsplit('.', 1)[0]}.0/24"
        except ValueError:
            subnet_str = "external-network"

        subnets[subnet_str].append(host)

        host_threats = list(threats.find({"host": host}))
        threat_count = len(host_threats)
        severities = [t.get("severity", "info").lower() for t in host_threats]

        highest_sev = "low"
        if "critical" in severities:
            highest_sev = "critical"
        elif "high" in severities:
            highest_sev = "high"
        elif "medium" in severities:
            highest_sev = "medium"

        open_ports = scan.get("open_port_count", 0)

        nodes.append({
            "id": host,
            "label": scan.get("hostname") or host,
            "type": "host",
            "subnet": subnet_str,
            "open_ports": open_ports,
            "threat_count": threat_count,
            "severity": highest_sev,
            "os_name": scan.get("os_detection", {}).get("name", "Unknown") if isinstance(scan.get("os_detection"), dict) else "Unknown",
        })

    for subnet_str, host_list in subnets.items():
        gw_id = f"gw-{subnet_str}"
        nodes.append({
            "id": gw_id,
            "label": f"Subnet {subnet_str}",
            "type": "gateway",
            "subnet": subnet_str,
            "host_count": len(host_list),
            "severity": "info",
        })

        for h in host_list:
            links.append({
                "source": gw_id,
                "target": h,
                "type": "subnet_link",
            })

    return jsonify({
        "status": "complete",
        "nodes": nodes,
        "links": links,
        "subnets_count": len(subnets),
        "total_hosts": len(seen_nodes),
    })


@app.route("/api/host/<path:ip>/history", methods=["GET"])
@login_required
def host_scan_history(ip):
    """Return paginated scan history for a specific host."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    ip = ip.strip()
    limit = _normalize_limit(request.args.get("limit", 10, type=int), 10, 50)

    scans = list(
        network_scans.find({"host": ip})
        .sort("scanned_at", -1)
        .limit(limit)
    )

    return jsonify({
        "status": "complete",
        "host": ip,
        "scan_count": len(scans),
        "scans": _serialize(scans),
    })


# ═════════════════════════════════════════════════════════════════════
#  API — Analyze & Deduplicate
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/analyze", methods=["POST"])
@login_required
def trigger_analysis():
    """Run AI analysis on scan data and merge duplicates. Requires authentication."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database is offline. Please start MongoDB."}), 503

    def background_analyze():
        try:
            from ai_logic import analyze_scan_results, merge_duplicates, compute_risk_scores  # type: ignore
            _log_activity("analysis_start", "AI multi-model analysis initiated (9 engines) in background")
            
            created = analyze_scan_results()
            scores = compute_risk_scores()
            removed = merge_duplicates()

            msg = f"Pipeline done: {created} threats, {len(scores)} hosts scored, {removed} deduped"
            _log_activity("analysis_complete", msg, "success")
            socketio.emit("analysis_complete", {"status": "success", "message": msg})
            socketio.emit("stats_update", {"total_threats": created})
            if created > 0:
                socketio.emit("threat_update", {"count": created})
        except Exception as e:
            msg = f"Analysis failed: {str(e)}"
            _log_activity("analysis_error", msg, "error")
            socketio.emit("analysis_complete", {"status": "error", "message": msg})

    try:
        _start_background_task(background_analyze)

        return jsonify({
            "status": "accepted",
            "message": "AI analysis started in the background. Check activity logs for completion."
        }), 202
    except Exception as e:
        _log_activity("analysis_error", f"Failed to start analysis thread: {str(e)}", "error")
        logger.error("Analysis trigger error: %s", e)
        return jsonify({"status": "error", "message": "An internal error occurred. Check server logs."}), 500


# ═════════════════════════════════════════════════════════════════════
#  API — Train ML Model
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/train", methods=["POST"])
@login_required
def trigger_training():
    """Trigger AI Machine Learning model training. Requires authentication."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database is offline. Please start MongoDB."}), 503

    def background_train():
        try:
            from ai_logic import train_ml_model  # type: ignore
            _log_activity("analysis_start", "ML model training initiated in background")
            success = train_ml_model()

            if success:
                _log_activity("analysis_complete", "ML model successfully trained on historical data", "success")
                socketio.emit("training_complete", {"status": "success", "message": "AI model trained successfully!"})
            else:
                _log_activity("analysis_error", "ML model training aborted (insufficient data or missing libs)", "error")
                socketio.emit("training_complete", {"status": "error", "message": "Training aborted: Ensure at least 20 threats exist."})
        except Exception as e:
            _log_activity("analysis_error", f"ML training failed: {str(e)}", "error")
            socketio.emit("training_complete", {"status": "error", "message": f"ML training failed: {str(e)}"})

    try:
        # Run training in the background to prevent HTTP timeout
        _start_background_task(background_train)

        return jsonify({
            "status": "accepted",
            "message": "AI model training started in the background. Check activity logs for completion."
        }), 202
    except Exception as e:
        _log_activity("analysis_error", f"Failed to start ML training thread: {str(e)}", "error")
        logger.error("Training trigger error: %s", e)
        return jsonify({"status": "error", "message": "An internal error occurred. Check server logs."}), 500


# ═════════════════════════════════════════════════════════════════════
#  API — Scan History
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/scan-history", methods=["GET"])
@login_required
def get_scan_history():
    """Return the last 20 scans grouped by scan_id."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    pipeline = [
        {"$group": {
            "_id": "$scan_id",
            "target": {"$first": "$target"},
            "host_count": {"$sum": 1},
            "scanned_at": {"$max": "$scanned_at"},
        }},
        {"$sort": {"scanned_at": -1}},
        {"$limit": 20},
    ]

    results = list(network_scans.aggregate(pipeline))
    return jsonify({"status": "complete", "scans": _serialize(results)})


# ═════════════════════════════════════════════════════════════════════
#  API — Export (CSV / JSON)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/export", methods=["GET"])
@login_required
def export_threats():
    """Export threats as CSV or JSON, with optional filtering by host/severity."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    fmt = request.args.get("format", "json").lower()
    host = (request.args.get("host") or "").strip()
    severity = (request.args.get("severity") or "").strip().lower()

    if fmt not in ALLOWED_EXPORT_FORMATS:
        return jsonify({"status": "error", "message": "Export format must be csv or json."}), 400
    if severity and severity not in ALLOWED_SEVERITIES:
        return jsonify({"status": "error", "message": "Invalid severity filter."}), 400

    # Build Filter Query
    query = {}
    if host:
        query["host"] = host
    if severity:
        query["severity"] = severity.lower()

    docs = list(threats.find(query).sort("detected_at", -1).limit(1000))
    
    # Activity logging
    log_msg = f"Threat data exported as {fmt.upper()} ({len(docs)} records)"
    if host: log_msg += f" for host {host}"
    _log_activity("export", log_msg)

    # Filename construction
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    base_name = f"nexshield_report_{timestamp}"
    if host:
        base_name = f"nexshield_report_{host.replace('.', '_')}_{timestamp}"
    filename = f"{base_name}.{fmt}"

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Severity", "Name", "Host", "CVE_ID", "Source", "Detail", "Detected_At"])
        for doc in docs:
            writer.writerow([
                doc.get("severity", "").upper(),
                doc.get("name", ""),
                doc.get("host", ""),
                doc.get("cve_id", ""),
                doc.get("source", ""),
                doc.get("detail", ""),
                doc.get("detected_at", "").strftime("%Y-%m-%d %H:%M:%S") if isinstance(doc.get("detected_at"), datetime) else str(doc.get("detected_at", "")),
            ])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # Default: JSON
    if _HAS_BSON:
        json_data = json_util.dumps(docs, indent=2)
    else:
        json_data = json.dumps(_serialize(docs), indent=2, default=str)
    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═════════════════════════════════════════════════════════════════════
#  API — CVE Lookup
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/cve/recent", methods=["GET"])
@login_required
def get_recent_cves():
    """Return recent CVEs directly from the local cvelistV5-main directory."""
    try:
        limit = _normalize_limit(request.args.get("limit", 50, type=int), 50, 100)
        from cve_lookup import CVELIST_DIR, _parse_cvelist_v5

        cves_dir = CVELIST_DIR
        if not cves_dir.exists():
            return jsonify({"status": "error", "message": f"Local CVE repository not found: {cves_dir}"}), 404
            
        years = sorted([d.name for d in cves_dir.iterdir() if d.is_dir() and d.name.isdigit()], reverse=True)
        recent_cves = []
        
        for year in years:
            year_dir = cves_dir / year
            blocks = []
            for d in year_dir.iterdir():
                if d.is_dir() and d.name.endswith("xxx"):
                    try:
                        blocks.append((int(d.name[:-3]), d))
                    except ValueError:
                        pass
                        
            blocks.sort(key=lambda x: x[0], reverse=True)
            
            for _, block_dir in blocks:
                files = sorted([f for f in block_dir.glob("*.json")], key=lambda x: x.name, reverse=True)
                for f in files:
                    parsed = _parse_cvelist_v5(f.stem)
                    if parsed:
                        recent_cves.append(parsed)
                        if len(recent_cves) >= limit:
                            return jsonify({"status": "complete", "cves": recent_cves})
                            
        return jsonify({"status": "complete", "cves": recent_cves})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/cve/<cve_id>", methods=["GET"])
@login_required
def cve_detail(cve_id):
    """Look up a CVE from the NVD database."""
    try:
        if not cve_id.upper().startswith("CVE-"):
            return jsonify({
                "status": "complete",
                "cve_id": cve_id.upper(),
                "description": "Internal NexShield detection or non-CVE identifier. This is not a public CVE.",
                "score": 0,
                "severity": "unknown",
                "references": []
            })
            
        cve_id = _validate_cve_id(cve_id)
        from cve_lookup import lookup_cve  # type: ignore
        result = lookup_cve(cve_id)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 404
        return jsonify({"status": "complete", **result})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/epss/<cve_id>", methods=["GET"])
@login_required
def epss_lookup(cve_id):
    """Query Exploit Prediction Scoring System (EPSS) metrics for a given CVE."""
    try:
        cve_id = _validate_cve_id(cve_id)
        from cve_lookup import get_epss_score  # type: ignore
        result = get_epss_score(cve_id)
        return jsonify({"status": "complete", "cve_id": cve_id, **result})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/nvd/cpe", methods=["GET"])
@login_required
def nvd_cpe_lookup():
    """Search CVEs by CPE name (e.g., cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*)."""
    cpe_name = (request.args.get("cpeName") or "").strip()
    if not cpe_name:
        return jsonify({"status": "error", "message": "cpeName parameter is required."}), 400
    try:
        from cve_lookup import lookup_by_cpe  # type: ignore
        limit = _normalize_limit(request.args.get("limit", 20, type=int), 20, 100)
        result = lookup_by_cpe(cpe_name, limit)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 502
        return jsonify({"status": "complete", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/nvd/tag", methods=["GET"])
@login_required
def nvd_tag_lookup():
    """Search CVEs by tag (e.g., disputed)."""
    tag = (request.args.get("cveTag") or "").strip()
    if not tag:
        return jsonify({"status": "error", "message": "cveTag parameter is required."}), 400
    try:
        from cve_lookup import lookup_by_tag  # type: ignore
        limit = _normalize_limit(request.args.get("limit", 20, type=int), 20, 100)
        result = lookup_by_tag(tag, limit)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 502
        return jsonify({"status": "complete", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/nvd/cvss-v2-metrics", methods=["GET"])
@login_required
def nvd_cvss_v2_metrics_lookup():
    """Search CVEs by CVSS v2 vector string (e.g., AV:N/AC:H/Au:N/C:C/I:C/A:C)."""
    vector = (request.args.get("cvssV2Metrics") or "").strip()
    if not vector:
        return jsonify({"status": "error", "message": "cvssV2Metrics parameter is required."}), 400
    try:
        from cve_lookup import lookup_by_cvss_v2_metrics  # type: ignore
        limit = _normalize_limit(request.args.get("limit", 20, type=int), 20, 100)
        result = lookup_by_cvss_v2_metrics(vector, limit)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 502
        return jsonify({"status": "complete", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/nvd/cvss-v2-severity", methods=["GET"])
@login_required
def nvd_cvss_v2_severity_lookup():
    """Search CVEs by CVSS v2 severity (LOW, MEDIUM, HIGH)."""
    severity = (request.args.get("cvssV2Severity") or "").strip()
    if not severity:
        return jsonify({"status": "error", "message": "cvssV2Severity parameter is required."}), 400
    try:
        from cve_lookup import lookup_by_cvss_v2_severity  # type: ignore
        limit = _normalize_limit(request.args.get("limit", 20, type=int), 20, 100)
        result = lookup_by_cvss_v2_severity(severity, limit)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 502
        return jsonify({"status": "complete", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/nvd/search", methods=["GET"])
@login_required
def nvd_universal_search():
    """Universal NVD search — auto-detects query type or accepts explicit type."""
    query = (request.args.get("q") or "").strip()
    query_type = (request.args.get("type") or "auto").strip()
    if not query:
        return jsonify({"status": "error", "message": "q (query) parameter is required."}), 400
    try:
        from cve_lookup import search_nvd  # type: ignore
        limit = _normalize_limit(request.args.get("limit", 20, type=int), 20, 100)
        result = search_nvd(query, query_type, limit)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 502
        return jsonify({"status": "complete", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/remediation/generate", methods=["GET"])
@login_required
def api_generate_remediation():
    """Generate automated remediation script for a target host (ansible, powershell, or bash)."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    host = request.args.get("host", "").strip()
    fmt = request.args.get("format", "ansible").strip().lower()

    if not host:
        return jsonify({"status": "error", "message": "host parameter is required."}), 400

    from remediation_generator import generate_remediation_script  # type: ignore
    host_threats = list(threats.find({"host": host}))

    script_content = generate_remediation_script(host_threats, target_host=host, fmt=fmt)
    return jsonify({
        "status": "complete",
        "host": host,
        "format": fmt,
        "threat_count": len(host_threats),
        "script": script_content,
    })


@app.route("/api/remediation/download", methods=["GET"])
@login_required
def api_download_remediation():
    """Download remediation script as a file attachment."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    host = request.args.get("host", "target").strip()
    fmt = request.args.get("format", "ansible").strip().lower()

    from remediation_generator import generate_remediation_script  # type: ignore
    host_threats = list(threats.find({"host": host}))

    script_content = generate_remediation_script(host_threats, target_host=host, fmt=fmt)

    ext_map = {"ansible": "yml", "powershell": "ps1", "bash": "sh"}
    ext = ext_map.get(fmt, "yml")
    mime_map = {"yml": "text/yaml", "ps1": "text/plain", "sh": "application/x-sh"}
    mime = mime_map.get(ext, "text/plain")

    filename = f"nexshield_remediation_{host.replace('.', '_')}.{ext}"
    response = make_response(script_content)
    response.headers["Content-Type"] = f"{mime}; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


# ═════════════════════════════════════════════════════════════════════
#  API — Activity Log
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/activity", methods=["GET"])
@login_required
def get_activity():
    """Return the last 50 activity log entries."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    docs = list(
        activity_log.find()
        .sort("timestamp", -1)
        .limit(50)
    )
    return jsonify({"status": "complete", "events": _serialize(docs)})

@app.route("/api/threats/raw", methods=["GET"])
@login_required
def get_raw_threats():
    """
    Returns raw, unpaginated threat data filtered by minimum severity.
    Used by the Exploit CLI to generate Metasploit RC scripts.
    """
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    min_severity = request.args.get("severity", "medium").lower()
    
    # Severity hierarchy
    sev_levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    target_level = sev_levels.get(min_severity, 2)
    
    allowed_sevs = [sev for sev, level in sev_levels.items() if level >= target_level]
    
    pipeline = [
        {"$match": {"severity": {"$in": allowed_sevs}}},
        {"$sort": {"severity": 1, "detected_at": -1}}
    ]
    
    docs = list(threats.aggregate(pipeline))
    return jsonify({"status": "complete", "threats": _serialize(docs), "count": len(docs)})

# Mapping common signatures to Metasploit modules
# ═════════════════════════════════════════════════════════════════════
#  Exploit Intelligence Database (v5.0)
# ═════════════════════════════════════════════════════════════════════

# EXPLOIT_DATABASE and MSF_MAPPINGS have been moved to msf_utils.py


@app.route("/api/exploit/generate", methods=["GET"])
@login_required
def api_generate_exploit_rc():
    """Generate and return a Metasploit RC script for a host or all hosts."""
    from flask import Response
    
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    host = request.args.get("host")
    preview = request.args.get("preview") == "true"
    query: dict[str, Any] = {"severity": {"$in": ["high", "critical"]}}
    if host:
        query["host"] = host
        
    docs = list(threats.find(query))
    if not docs:
        msg = "[-] No high/critical threats found to exploit."
        return jsonify({"status": "error", "message": msg}) if preview else (msg, 404)
        
    rc_lines = [
        "# NexShield Auto-Generated Metasploit Script",
        f"# Targets: {host if host else 'All High/Critical Hosts'}",
        "spool msf_nexshield_session.log",
        "setg VERBOSE true",
        ""
    ]
    
    modules_added = set()
    for t in docs:
        t_host = t.get("host")
        detail = str(t.get("detail") or "").lower()
        name = str(t.get("name") or "").lower()
        cve = str(t.get("cve_id") or "").lower()
        
        module = None
        for keyword, mod in MSF_MAPPINGS.items():
            if keyword in detail or keyword in name or keyword in cve:
                module = mod
                break
        
        if not module:
            module = "auxiliary/scanner/portscan/tcp"
                
        if module:
            combo_key = f"{t_host}_{module}"
            if combo_key not in modules_added:
                rc_lines.extend([
                    f"# Target: {t_host} - {t.get('name')}",
                    f"use {module}",
                    f"set RHOSTS {t_host}",
                    "set LHOST eth0  # Update this if needed",
                    "exploit -j",
                    ""
                ])
                modules_added.add(combo_key)
                
    if not modules_added:
        msg = "[-] Could not map any discovered threats to known Metasploit modules."
        return jsonify({"status": "error", "message": msg}) if preview else (msg, 404)
        
    content = "\n".join(rc_lines)
    
    if preview:
        return jsonify({"status": "complete", "script": content})
        
    filename = f"exploit_{host.replace('.', '_') if host else 'all'}.rc"
    return Response(content, mimetype="text/plain", headers={"Content-Disposition": f"attachment;filename={filename}"})


@app.route("/api/exploit/execute", methods=["POST"])
@login_required
def api_execute_exploit():
    """Trigger live Metasploit execution via RPC. Requires authentication."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    ip_key = f"exploit:{request.remote_addr}"
    if _rate_limit(ip_key, max_requests=5, window_sec=60):
        return jsonify({"status": "error", "message": "Rate limit exceeded for exploit execution."}), 429

    data = request.get_json(silent=True) or {}
    try:
        host = _validate_host(data.get("host"))
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
        
    query = {"host": host, "severity": {"$in": ["high", "critical"]}}
    docs = list(threats.find(query))
    
    if not docs:
        return jsonify({"status": "error", "message": f"No high/critical threats found for {host}."}), 404
        
    module_to_run = None
    for t in docs:
        detail = str(t.get("detail") or "").lower()
        name = str(t.get("name") or "").lower()
        cve = str(t.get("cve_id") or "").lower()
        
        for keyword, mod in MSF_MAPPINGS.items():
            if keyword in detail or keyword in name or keyword in cve:
                module_to_run = mod
                break
        if module_to_run:
            break
            
    if not module_to_run:
        module_to_run = "auxiliary/scanner/portscan/tcp"
        _log_activity("exploit_fallback", f"No specific MSF module found for {host}. Falling back to generic TCP scan.", "warning")
    try:
        from msf_rpc import execute_exploit  # type: ignore
        result = execute_exploit(host, module_to_run)
        _log_activity("exploit_launched", f"Launched {module_to_run} against {host}", "warning")
        return jsonify(result)
    except Exception as e:
        logger.error("Exploit execution error: %s", e)
        return jsonify({"status": "error", "message": "An internal error occurred. Check server logs."}), 500


# ═════════════════════════════════════════════════════════════════════
#  API — Host Risk Scores
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/risk-scores", methods=["GET"])
@login_required
def get_risk_scores():
    """
    Returns composite risk scores per host.
    Logic delegated to ai_logic for consistency across the analysis pipeline.
    """
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    scores = compute_risk_scores(persist=False) # Don't re-tag every GET
    
    # Format for frontend grid
    formatted = []
    for host, data in scores.items():
        formatted.append({
            "host": host,
            "score": data["score"],
            "risk_level": data["risk_level"],
            "threat_count": data["threat_count"],
            "engines_flagged": data["engines_flagged"]
        })

    return jsonify({"status": "complete", "scores": formatted})


# ═════════════════════════════════════════════════════════════════════
#  API — Threat Trends (Severity Distribution + Type Breakdown)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/threat-trends", methods=["GET"])
@login_required
def get_threat_trends():
    """Return severity distribution and threat source breakdown."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    # Severity distribution
    sev_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    sev_results = list(threats.aggregate(sev_pipeline))
    severity_dist = {r["_id"]: r["count"] for r in sev_results if r["_id"]}

    # Source engine breakdown
    src_pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    src_results = list(threats.aggregate(src_pipeline))
    source_dist = {r["_id"]: r["count"] for r in src_results if r["_id"]}

    # Tag frequency
    tag_pipeline = [
        {"$unwind": "$tags"},
        {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 15},
    ]
    try:
        tag_results = list(threats.aggregate(tag_pipeline))
        tags = {r["_id"]: r["count"] for r in tag_results if r["_id"]}
    except Exception:
        tags = {}

    return jsonify({
        "status": "complete",
        "severity_distribution": severity_dist,
        "source_distribution": source_dist,
        "tag_frequency": tags,
    })


@app.route("/api/threat/<tid>/notes", methods=["POST"])
@login_required
def add_threat_note(tid):
    """Add an analyst note to a threat."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    body = request.get_json(silent=True) or {}
    note_text = (body.get("note") or "").strip()
    if not note_text or len(note_text) > 2000:
        return jsonify({"status": "error", "message": "Note must be 1-2000 characters."}), 400

    # Find the threat
    if _HAS_BSON:
        from bson import ObjectId
        try:
            query = {"_id": ObjectId(tid)}
        except Exception:
            return jsonify({"status": "error", "message": "Invalid threat ID."}), 400
    else:
        query = {"_id": tid}

    doc = threats.find_one(query)
    if not doc:
        return jsonify({"status": "error", "message": "Threat not found."}), 404

    note = {
        "author": session.get("user", "unknown"),
        "text": note_text,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    existing_notes = doc.get("notes", [])
    if not isinstance(existing_notes, list):
        existing_notes = []
    existing_notes.append(note)

    threats.update_one(query, {"$set": {"notes": existing_notes}})
    _log_activity("analyst", f"Note added to threat {tid} by {session.get('user')}")

    return jsonify({"status": "complete", "message": "Note added.", "note": note})


@app.route("/api/threats/bulk-action", methods=["POST"])
@login_required
def bulk_threat_action():
    """Perform bulk actions on multiple threats. Requires authentication."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    body = request.get_json(silent=True) or {}
    action = (body.get("action") or "").strip().lower()
    threat_ids = body.get("threat_ids", [])

    if action not in ("acknowledge", "dismiss", "escalate"):
        return jsonify({"status": "error", "message": "Action must be acknowledge, dismiss, or escalate."}), 400
    if not threat_ids or not isinstance(threat_ids, list):
        return jsonify({"status": "error", "message": "threat_ids must be a non-empty list."}), 400
    if len(threat_ids) > 100:
        return jsonify({"status": "error", "message": "Maximum 100 threats per bulk action."}), 400

    update_map = {
        "acknowledge": {"$set": {"acknowledged": True, "acknowledged_by": session.get("user")}},
        "dismiss": {"$set": {"severity": "low", "detail": "[DISMISSED] "}},
        "escalate": {"$set": {"severity": "critical", "detail": "[ESCALATED] "}},
    }

    modified = 0
    for tid in threat_ids:
        try:
            if _HAS_BSON:
                from bson import ObjectId
                q = {"_id": ObjectId(tid)}
            else:
                q = {"_id": tid}
            result = threats.update_one(q, update_map[action])
            modified += result.modified_count
        except Exception:
            continue

    _log_activity("analyst", f"Bulk {action} on {modified} threats by {session.get('user')}", "info")
    return jsonify({"status": "complete", "message": f"{action.title()}d {modified} threats.", "modified": modified})


# ═════════════════════════════════════════════════════════════════════
#  API — Pentest Report Generator
# ═════════════════════════════════════════════════════════════════════

# Severity-based remediation templates for auto-generated reports
_REMEDIATION_MAP = {
    "SMB Exposed":            "Disable SMBv1, restrict SMB to internal VLANs, enforce SMB signing.",
    "RDP Exposed":            "Restrict RDP to VPN-only, enable NLA, enforce MFA, use RD Gateway.",
    "SSH Exposed":             "Disable password auth, enforce key-based auth, restrict to bastion hosts.",
    "Telnet Exposed":         "Disable Telnet entirely, replace with SSH.",
    "FTP Exposed":            "Replace FTP with SFTP/SCP, disable anonymous access.",
    "Redis Exposed":          "Set requirepass, bind to 127.0.0.1, disable FLUSHALL/CONFIG.",
    "MongoDB Exposed":        "Enable authentication, bind to localhost, use TLS.",
    "Elasticsearch Exposed":  "Enable X-Pack security, restrict to internal network.",
    "MySQL Exposed":          "Restrict to app-tier IPs, rotate default credentials.",
    "PostgreSQL Exposed":     "Restrict pg_hba.conf, enforce SSL connections.",
    "VNC Exposed":            "Disable VNC or tunnel through SSH, enforce strong passwords.",
    "Kubernetes API Exposed": "Restrict API server to private network, enable RBAC.",
    "Unencrypted":            "Migrate to encrypted protocol variant, enforce TLS 1.2+.",
    "Default Credentials":    "Rotate all default passwords, enforce complexity policies.",
    "Credential Dump Risk":   "Implement LSA protection, restrict Kerberos delegation.",
    "Persistence Vector":     "Audit cron/scheduled tasks, monitor web directories for shells.",
    "DLL Hijack Risk":        "Enforce code signing, audit DLL search paths, use SafeDllSearchMode.",
}


@app.route("/api/report", methods=["GET"])
@login_required
def generate_report():
    """
    Generate a structured penetration testing report from live scan data.
    Returns JSON with: executive summary, host inventory, vulnerability findings,
    risk scores, MITRE ATT&CK coverage, and remediation recommendations.
    """
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    try:
        from ai_logic import MODELS, MITRE_TECHNIQUES, SEVERITY_WEIGHTS  # type: ignore

        # ── 1. Executive Summary ─────────────────────────────────
        total_threats = threats.count_documents({})
        total_scans = network_scans.count_documents({})
        sev_counts = {
            "critical": threats.count_documents({"severity": "critical"}),
            "high":     threats.count_documents({"severity": "high"}),
            "medium":   threats.count_documents({"severity": "medium"}),
            "low":      threats.count_documents({"severity": "low"}),
        }

        unique_hosts = threats.distinct("host")
        unique_cves = [c for c in threats.distinct("cve_id") if c and c.startswith("CVE-")]
        engines_active = threats.distinct("source")

        # Overall risk assessment
        if sev_counts["critical"] > 5:
            overall_risk = "CRITICAL"
            overall_summary = "Multiple critical vulnerabilities detected. Immediate remediation required."
        elif sev_counts["critical"] > 0 or sev_counts["high"] > 10:
            overall_risk = "HIGH"
            overall_summary = "Significant vulnerabilities present. Prioritize patching and access controls."
        elif sev_counts["high"] > 0:
            overall_risk = "MEDIUM"
            overall_summary = "Moderate risk detected. Address high-severity findings within 2 weeks."
        else:
            overall_risk = "LOW"
            overall_summary = "Minimal vulnerabilities detected. Continue regular monitoring."

        executive_summary = {
            "overall_risk": overall_risk,
            "summary": overall_summary,
            "total_threats": total_threats,
            "total_hosts_scanned": total_scans,
            "unique_hosts_affected": len(unique_hosts),
            "severity_breakdown": sev_counts,
            "unique_cves": len(unique_cves),
            "engines_active": len(engines_active),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # ── 2. Target Environment ────────────────────────────────
        host_pipeline = [
            {"$group": {
                "_id": "$host",
                "hostname": {"$first": "$hostname"},
                "state": {"$first": "$state"},
                "os_name": {"$first": "$os_detection.name"},
                "os_accuracy": {"$first": "$os_detection.accuracy"},
                "os_family": {"$first": "$os_detection.family"},
                "open_ports": {"$max": "$open_port_count"},
                "services": {"$first": "$services_detected"},
                "scan_types": {"$addToSet": "$scan_type"},
                "latest_scan": {"$max": "$scanned_at"},
                "mac_address": {"$first": "$mac_address"},
                "mac_vendor": {"$first": "$mac_vendor"},
            }},
            {"$sort": {"open_ports": -1}},
            {"$limit": 100},
        ]
        host_docs = list(network_scans.aggregate(host_pipeline))
        target_environment = []
        for h in host_docs:
            if not h["_id"]:
                continue
            target_environment.append({
                "host": h["_id"],
                "hostname": h.get("hostname", ""),
                "state": h.get("state", "unknown"),
                "os": h.get("os_name", "Unknown"),
                "os_accuracy": h.get("os_accuracy", 0),
                "os_family": h.get("os_family", ""),
                "open_ports": h.get("open_ports", 0),
                "services": h.get("services", []),
                "scan_types_used": h.get("scan_types", []),
                "last_scanned": _serialize(h.get("latest_scan")),
                "mac_address": h.get("mac_address", ""),
                "mac_vendor": h.get("mac_vendor", ""),
            })

        # ── 3. Vulnerability Findings (grouped by host) ──────────
        findings_pipeline = [
            {"$sort": {"detected_at": -1}},
            {"$group": {
                "_id": "$host",
                "threats": {"$push": {
                    "name": "$name",
                    "severity": "$severity",
                    "cve_id": "$cve_id",
                    "source": "$source",
                    "detail": "$detail",
                    "tags": "$tags",
                    "detected_at": "$detected_at",
                }},
                "critical_count": {"$sum": {"$cond": [{"$eq": ["$severity", "critical"]}, 1, 0]}},
                "high_count": {"$sum": {"$cond": [{"$eq": ["$severity", "high"]}, 1, 0]}},
                "total": {"$sum": 1},
            }},
            {"$sort": {"critical_count": -1, "high_count": -1}},
        ]
        findings_raw = list(threats.aggregate(findings_pipeline))
        vulnerability_findings = []
        # Enriching data...
        for f in findings_raw:
            if not f["_id"]:
                continue
            
            # Enrich threats with deep Metasploit intelligence
            enriched_threats = []
            for t in f["threats"]:
                intel = None
                d_low = str(t.get("detail") or "").lower()
                n_low = str(t.get("name") or "").lower()
                c_low = str(t.get("cve_id") or "").lower()
                
                # Check for detailed intel first
                for keyword, info in EXPLOIT_DATABASE.items():
                    if keyword in d_low or keyword in n_low or keyword in c_low:
                        intel = info
                        break
                
                if intel:
                    t["exploit_module"] = intel["module"]
                    t["exploit_rank"] = intel["rank"]
                    t["exploit_reliability"] = intel["reliability"]
                    t["exploit_desc"] = intel["desc"]
                    t["exploit_check"] = intel["check"]
                else:
                    # Fallback to simple mapping
                    m_path = ""
                    for k, m in MSF_MAPPINGS.items():
                        if k in d_low or k in n_low or k in c_low:
                            m_path = m; break
                    t["exploit_module"] = m_path
                    t["exploit_rank"] = "NORMAL"
                    t["exploit_reliability"] = "UNKNOWN"
                    t["exploit_desc"] = "Generic mapping detected."
                    t["exploit_check"] = False

                enriched_threats.append(t)

            vulnerability_findings.append({
                "host": f["_id"],
                "total_threats": f["total"],
                "critical": f["critical_count"],
                "high": f["high_count"],
                "threats": _serialize(enriched_threats[:50]),
            })

        # ── 4. Risk Scores ───────────────────────────────────────
        scores = compute_risk_scores(persist=False)
        risk_scores = [
            {
                "host": host,
                "score": data["score"],
                "risk_level": data["risk_level"],
                "threat_count": data["threat_count"],
                "engines_flagged": data["engines_flagged"],
                "critical_count": data.get("critical_count", 0),
            }
            for host, data in sorted(scores.items(), key=lambda x: -x[1]["score"])
        ]

        # ── 5. MITRE ATT&CK Coverage ─────────────────────────────
        tag_pipeline = [
            {"$unwind": "$tags"},
            {"$match": {"tags": {"$regex": "^T\\d{4}"}}},
            {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        try:
            mitre_raw = list(threats.aggregate(tag_pipeline))
        except Exception:
            mitre_raw = []

        mitre_coverage = []
        for m in mitre_raw:
            technique_id = m["_id"]
            mitre_coverage.append({
                "technique_id": technique_id,
                "technique_name": MITRE_TECHNIQUES.get(technique_id, "Unknown"),
                "occurrences": m["count"],
            })

        # ── 6. Recommendations ───────────────────────────────────
        recommendations = []
        seen_recs = set()

        # Generate recommendations from threat names
        all_threat_names = threats.distinct("name")
        for threat_name in all_threat_names:
            for pattern, remediation in _REMEDIATION_MAP.items():
                if pattern.lower() in str(threat_name).lower() and pattern not in seen_recs:
                    # Determine priority from severity
                    sample = threats.find_one({"name": threat_name})
                    sev = sample.get("severity", "medium") if sample else "medium"
                    priority = "P0 — Immediate" if sev == "critical" else "P1 — High" if sev == "high" else "P2 — Medium"

                    recommendations.append({
                        "finding": pattern,
                        "priority": priority,
                        "remediation": remediation,
                        "affected_hosts": threats.count_documents({"name": {"$regex": pattern, "$options": "i"}}),
                    })
                    seen_recs.add(pattern)
                    break

        # Sort by priority
        priority_order = {"P0 — Immediate": 0, "P1 — High": 1, "P2 — Medium": 2}
        recommendations.sort(key=lambda r: priority_order.get(r["priority"], 3))

        # ── 7. Scan Metadata ─────────────────────────────────────
        latest_scan = network_scans.find_one(sort=[("scanned_at", -1)])
        scan_metadata = {
            "total_scan_records": total_scans,
            "latest_scan_id": latest_scan.get("scan_id", "") if latest_scan else "",
            "latest_scan_time": _serialize(latest_scan.get("scanned_at")) if latest_scan else None,
            "nmap_version": latest_scan.get("nmap_version", "") if latest_scan else "",
            "scan_types_used": list(network_scans.distinct("scan_type")),
            "engine_registry": {k: v for k, v in MODELS.items()},
        }

        # ── Assemble Final Report ─────────────────────────────────
        report = {
            "status": "complete",
            "report_title": "NexShield Penetration Testing Report",
            "report_version": "2.0",
            "executive_summary": executive_summary,
            "target_environment": target_environment,
            "vulnerability_findings": vulnerability_findings,
            "risk_scores": risk_scores,
            "mitre_attack_coverage": mitre_coverage,
            "recommendations": recommendations,
            "scan_metadata": scan_metadata,
        }

        _log_activity("report", f"Pentest report generated: {total_threats} threats, {len(unique_hosts)} hosts", "info")
        socketio.emit("report_generated", {"status": "success", "message": f"Report generated with {total_threats} findings"})

        return jsonify(report)

    except Exception as e:
        _log_activity("report_error", f"Report generation failed: {str(e)}", "error")
        return jsonify({"status": "error", "message": f"Report generation failed: {str(e)}"}), 500


@app.route("/api/report/download-rc", methods=["GET"])
@login_required
def download_report_rc():
    """
    Generate an RC script for all weaponized threats in the database.
    """
    if not check_connection():
        return "Database unavailable", 503

    try:
        all_threats = list(threats.find())
        rc_lines = ["# NexShield v5 Intelligence-to-Action RC Script", f"# Generated at: {datetime.now().isoformat()}", ""]
        added = set()

        for t in all_threats:
            d = str(t.get("detail") or "").lower()
            n = str(t.get("name") or "").lower()
            c = str(t.get("cve_id") or "").lower()
            h = t.get("host")
            
            for keyword, mod in MSF_MAPPINGS.items():
                if keyword in d or keyword in n or keyword in c:
                    if (h, mod) not in added:
                        rc_lines.append(f"# Threat: {t.get('name')}")
                        rc_lines.append(f"use {mod}")
                        rc_lines.append(f"set RHOSTS {h}")
                        rc_lines.append(f"set LHOST eth0")
                        rc_lines.append("exploit -j")
                        rc_lines.append("")
                        added.add((h, mod))
                    break
        
        if len(rc_lines) <= 3:
            return "No weaponized threats found.", 404

        response = make_response("\n".join(rc_lines))
        response.headers["Content-Disposition"] = "attachment; filename=nexshield_v5_operation.rc"
        response.headers["Content-Type"] = "text/plain"
        return response

    except Exception as e:
        return str(e), 500


# ═════════════════════════════════════════════════════════════════════
#  Run
# ═════════════════════════════════════════════════════════════════════

def _provision_admin_user():
    """Initialize or sync the default admin account. Always refreshes the password hash on startup."""
    try:
        if not check_connection():
            logger.warning("Cannot provision admin: Database unavailable")
            return False

        default_username = os.environ.get("ADMIN_USERNAME", "admin")
        default_password = os.environ.get("ADMIN_PASSWORD", "admin")
        password_hash = generate_password_hash(default_password)

        # Find existing admin user (case-insensitive)
        existing = users.find_one({"username": default_username})
        if not existing:
            existing = users.find_one({"username": {"$regex": f"^{re.escape(default_username)}$", "$options": "i"}})

        # Clean up any duplicate admin accounts (e.g. "Admin" + "admin")
        all_admins = list(users.find({"role": "admin"}))
        if len(all_admins) > 1:
            # Keep only the first one, remove duplicates
            for dup in all_admins[1:]:
                users.delete_many({"username": dup["username"]})
            logger.info("Cleaned up %d duplicate admin account(s)", len(all_admins) - 1)

        if existing:
            # Always sync username and password hash on startup
            users.update_one(
                {"username": existing["username"]},
                {"$set": {
                    "username": default_username,
                    "password_hash": password_hash,
                    "role": "admin",
                }},
            )
            logger.info("Admin account synced: %s", default_username)
            return True

        # Create fresh admin account
        users.insert_one({
            "username": default_username,
            "password_hash": password_hash,
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
        })
        logger.info("Default admin account created: %s", default_username)
        _log_activity("auth", "Default admin account created")
        return True
    except Exception as e:
        logger.error("Failed to provision admin account: %s", e, exc_info=True)
        return False


def _startup_banner():
    """Display startup information."""
    is_prod = os.environ.get("FLASK_ENV") == "production"
    environment = "PRODUCTION" if is_prod else "DEVELOPMENT"
    
    port = os.environ.get("PORT", "5000")
    print("\n" + "=" * 70)
    print("   NexShield v6.0 — AI-Powered Threat Intelligence Platform")
    print(f"   Environment: {environment}")
    print(f"   Dashboard: http://127.0.0.1:{port}")
    print("   Docs: https://github.com/nextboxis/NexShield")
    print("=" * 70 + "\n")
    
    logger.info(f"NexShield starting in {environment} mode")


if __name__ == "__main__":
    import sys
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("nexshield.log", encoding="utf-8")
        ]
    )
    
    _startup_banner()
    
    # Provision admin user
    _provision_admin_user()
    
    # Log startup
    _log_activity("system", "NexShield platform started", "info")
    
    # Production vs Development mode
    is_production = os.environ.get("FLASK_ENV", "development") == "production"
    
    if is_production:
        logger.warning("⚠️  Running in PRODUCTION mode. Use a proper WSGI server (Gunicorn/Waitress).")
        logger.warning("   Example: gunicorn -w 4 -b 0.0.0.0:5000 'app:app'")
        # For production, the app should be run with gunicorn/waitress
        # This fallback uses the development server with warnings disabled
        socketio.run(
            app,
            debug=False,
            host="127.0.0.1",
            port=int(os.environ.get("PORT", 5000)),
            use_reloader=False,
            use_debugger=False,
            allow_unsafe_werkzeug=True,
        )
    else:
        logger.info("⚠️  Running in DEVELOPMENT mode")
        socketio.run(
            app,
            debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
            host="127.0.0.1",
            port=int(os.environ.get("PORT", 5000)),
            allow_unsafe_werkzeug=True,
        )


# ═════════════════════════════════════════════════════════════════════
#  API — Single Threat Lookup
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/threat/<tid>", methods=["GET"])
@login_required
def get_threat(tid):
    """Return a single threat document by ID."""
    if _HAS_BSON:
        from bson import ObjectId  # type: ignore
        try:
            oid = ObjectId(tid)
        except Exception:
            return jsonify({"status": "error", "message": "Invalid id"}), 400
        doc = threats.find_one({"_id": oid})
    else:
        # TinyDB: search by string _id
        doc = threats.find_one({"_id": tid})

    if not doc:
        return jsonify({"status": "error", "message": "Not found"}), 404

    return jsonify({"status": "complete", "threat": _serialize(doc)})

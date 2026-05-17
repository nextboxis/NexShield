"""
routes.auth — Authentication Blueprint for NexShield
======================================================
Handles login, logout, registration, session checks, and WebSocket auth.
"""

import os
import re
import secrets
import logging
import time as _time
from collections import defaultdict
from typing import List
from functools import wraps
from datetime import datetime, timezone

from flask import Blueprint, request, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore

from db import users, activity_log, check_connection

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)

# ─── Validation ─────────────────────────────────────────────────────
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_RE = re.compile(r"^.{5,128}$")

# ─── Rate Limiter ───────────────────────────────────────────────────
_rate_limit_store: dict[str, List[float]] = defaultdict(list)


def _rate_limit(key: str, max_requests: int = 10, window_sec: int = 60) -> bool:
    """Returns True if rate limit is exceeded."""
    now = _time.time()
    _rate_limit_store[key] = [t for t in _rate_limit_store[key] if now - t < window_sec]
    if len(_rate_limit_store[key]) >= max_requests:
        return True
    _rate_limit_store[key].append(now)
    return False


# ─── Helpers ────────────────────────────────────────────────────────
def _log_activity(event_type, message, severity="info"):
    """Centralized logging utility."""
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


def _validate_username(username):
    candidate = (username or "").strip()
    if not USERNAME_RE.fullmatch(candidate):
        raise ValueError("Username must be 3-32 characters and use only letters, numbers, ., _, or -.")
    return candidate


def _find_user_by_username(username: str):
    """Find a user by username (case-insensitive)."""
    candidate = (username or "").strip()
    if not candidate:
        return None
    exact = users.find_one({"username": candidate})
    if exact:
        return exact
    return users.find_one({
        "username": {"$regex": f"^{re.escape(candidate)}$", "$options": "i"}
    })


def login_required(f):
    """Decorator: rejects unauthenticated requests with HTTP 401."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"status": "error", "message": "Authentication required."}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Auth Token ─────────────────────────────────────────────────────
WS_TOKEN = os.environ.get("WS_TOKEN", secrets.token_hex(16))


@auth_bp.route("/api/auth/token", methods=["GET"])
def get_ws_token():
    """Returns the WebSocket authorization token. Requires authentication."""
    if "user" not in session:
        return jsonify({"status": "error", "message": "Authentication required."}), 401
    return jsonify({"status": "complete", "token": WS_TOKEN})


# ─── Registration ───────────────────────────────────────────────────
@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user account."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database offline."}), 503

    ip_key = f"register:{request.remote_addr}"
    if _rate_limit(ip_key, max_requests=5, window_sec=300):
        return jsonify({"status": "error", "message": "Too many registration attempts. Try again later."}), 429

    body = request.get_json(silent=True) or {}
    try:
        username = _validate_username(body.get("username"))
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    password = (body.get("password") or "").strip()
    if not PASSWORD_RE.fullmatch(password):
        return jsonify({"status": "error", "message": "Password must be 5-128 characters."}), 400

    if _find_user_by_username(username):
        return jsonify({"status": "error", "message": "Username already taken."}), 409

    users.insert_one({
        "username": username,
        "password_hash": generate_password_hash(password),
        "role": "analyst",
        "created_at": datetime.now(timezone.utc),
    })
    _log_activity("auth", f"New user registered: {username}")
    return jsonify({"status": "complete", "message": f"User '{username}' created."}), 201


# ─── Login ──────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/login", methods=["POST"])
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

    user_doc = _find_user_by_username(username)
    if not user_doc or not check_password_hash(user_doc["password_hash"], password):
        _log_activity("security", f"Failed login attempt for '{username}' from {request.remote_addr}", "warning")
        return jsonify({"status": "error", "message": "Invalid credentials."}), 401

    from flask import current_app
    session.permanent = True
    session["user"] = user_doc["username"]
    session["role"] = user_doc.get("role", "analyst")
    session["_boot_id"] = current_app.config["BOOT_ID"]
    _log_activity("auth", f"User '{username}' logged in from {request.remote_addr}")
    canonical = session["user"]
    return jsonify({
        "status": "complete",
        "message": f"Welcome, {canonical}.",
        "user": canonical,
        "role": session["role"],
    })


# ─── Logout ─────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    """End the current session."""
    username = session.pop("user", "unknown")
    session.clear()
    _log_activity("auth", f"User '{username}' logged out")
    return jsonify({"status": "complete", "message": "Logged out."})


# ─── Session Check ──────────────────────────────────────────────────
@auth_bp.route("/api/auth/session", methods=["GET"])
def check_session():
    """Check if the current session is authenticated."""
    if "user" in session:
        return jsonify({"status": "complete", "authenticated": True, "user": session["user"], "role": session.get("role", "analyst")})
    return jsonify({"status": "complete", "authenticated": False})


# ─── Admin Provisioning ─────────────────────────────────────────────
def provision_admin_user(default_username: str = "Admin", default_password: str = "ADMIN") -> bool:
    """Initialize or sync the default Admin account."""
    try:
        if not check_connection():
            logger.warning("Cannot provision admin: Database unavailable")
            return False

        password_hash = generate_password_hash(default_password)
        existing = _find_user_by_username(default_username)
        if not existing:
            existing = _find_user_by_username("admin")

        if existing:
            users.update_one(
                {"username": existing["username"]},
                {"$set": {
                    "username": default_username,
                    "password_hash": password_hash,
                    "role": "admin",
                }},
            )
            logger.info("Default admin account synced (%s)", default_username)
            return True

        users.insert_one({
            "username": default_username,
            "password_hash": password_hash,
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
        })
        logger.info("Default admin account created (%s)", default_username)
        _log_activity("auth", f"Default admin account created: {default_username}")
        return True
    except Exception as e:
        logger.error("Failed to provision admin account: %s", e, exc_info=True)
        return False

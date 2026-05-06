"""
config.py — MongoDB Configuration for Threat Intelligence Platform
"""

import os
import time
from pymongo import MongoClient  # type: ignore

# ─── MongoDB Connection ──────────────────────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("MONGO_DB", "threat_intel")

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client[DB_NAME]

# ─── Collections ─────────────────────────────────────────────────────
network_scans = db["network_scans"]
threats = db["threats"]
activity_log = db["activity_log"]
cve_cache = db["cve_cache"]
users = db["users"]
ip_geo_cache = db["ip_geo_cache"]       # Geolocation lookup cache
scan_jobs = db["scan_jobs"]             # Scan job queue & history

# ─── Connection Check (cached for 5 seconds) ────────────────────────
_conn_cache = {"ok": False, "checked_at": 0}
_CONN_CACHE_TTL = 5  # seconds


def check_connection():
    """Return True if MongoDB is reachable. Caches result for 5s."""
    now = time.time()
    if now - _conn_cache["checked_at"] < _CONN_CACHE_TTL:
        return _conn_cache["ok"]
    try:
        client.admin.command("ping")
        _conn_cache["ok"] = True
    except Exception:
        _conn_cache["ok"] = False
    _conn_cache["checked_at"] = now
    return _conn_cache["ok"]

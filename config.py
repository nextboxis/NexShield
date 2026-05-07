"""
config.py — MongoDB Configuration for Threat Intelligence Platform
"""

import os
import time
from typing import Any
from pymongo.collection import Collection
from pymongo import MongoClient  # type: ignore
from pymongo.database import Database

# ─── MongoDB Connection ──────────────────────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("MONGO_DB", "threat_intel")

client: MongoClient[Any] = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db: Database[Any] = client[DB_NAME]

# ─── Collections ─────────────────────────────────────────────────────
network_scans: Collection[Any] = db["network_scans"]
threats: Collection[Any] = db["threats"]
activity_log: Collection[Any] = db["activity_log"]
cve_cache: Collection[Any] = db["cve_cache"]
users: Collection[Any] = db["users"]
ip_geo_cache: Collection[Any] = db["ip_geo_cache"]       # Geolocation lookup cache
scan_jobs: Collection[Any] = db["scan_jobs"]             # Scan job queue & history

# ─── Connection Check (cached for 5 seconds) ────────────────────────
_conn_cache: dict[str, Any] = {"ok": False, "checked_at": 0}
_CONN_CACHE_TTL = 5  # seconds


def check_connection() -> bool:
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

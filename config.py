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

_db_ready = False
try:
    _real_client: Any = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    _real_client.admin.command("ping")
    print("   [+] Connected to real MongoDB.")
    client = _real_client
    _db_ready = True
except Exception:
    if '_real_client' in locals() and _real_client:
        _real_client.close()  # THIS KILLS THE BACKGROUND THREAD
    try:
        import mongomock # type: ignore
        print("   [!] MongoDB not found. Falling back to in-memory mongomock.")
        client = mongomock.MongoClient()
        _db_ready = True
    except ImportError:
        print("   [!] MongoDB not found and mongomock not installed.")
        client = None
        _db_ready = False

if client:
    db: Any = client[DB_NAME]
    network_scans: Any = db["network_scans"]
    threats: Any = db["threats"]
    activity_log: Any = db["activity_log"]
    cve_cache: Any = db["cve_cache"]
    users: Any = db["users"]
    ip_geo_cache: Any = db["ip_geo_cache"]       # Geolocation lookup cache
    scan_jobs: Any = db["scan_jobs"]             # Scan job queue & history
else:
    # Dummy objects to prevent import errors if completely disconnected
    class DummyCollection:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None
    db = DummyCollection()
    network_scans = threats = activity_log = cve_cache = users = ip_geo_cache = scan_jobs = DummyCollection()

# ─── Connection Check ────────────────────────────────────────────────
def check_connection() -> bool:
    """Return True if MongoDB (or mock) is reachable."""
    return _db_ready

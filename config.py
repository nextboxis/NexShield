"""
config.py — MongoDB Configuration for Threat Intelligence Platform
"""

import os
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


def check_connection():
    """Return True if MongoDB is reachable, False otherwise."""
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False

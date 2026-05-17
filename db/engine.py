"""
db.engine — Database Initialization Engine for NexShield
=========================================================
Handles backend selection (TinyDB vs MongoDB), initialization,
and exposes collection references.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ─── Load .env automatically ────────────────────────────────────────
try:
    from dotenv import load_dotenv  # type: ignore
    _env_path = Path(__file__).parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
        print("   [+] Loaded .env configuration file.")
    else:
        _example_path = Path(__file__).parent.parent / ".env.example"
        if _example_path.exists():
            import shutil
            shutil.copy2(_example_path, _env_path)
            load_dotenv(_env_path)
            print("   [+] Created .env from .env.example (edit it to customize).")
except ImportError:
    pass


# ─── Configuration ──────────────────────────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
DB_NAME = os.environ.get("MONGO_DB", "threat_intel")
DATA_DIR = Path(__file__).parent.parent / "data"

_db_ready = False
_using_mongodb = False


# ═════════════════════════════════════════════════════════════════════
#  Database Initialization
# ═════════════════════════════════════════════════════════════════════

def _init_tinydb():
    """Initialize TinyDB as the database backend."""
    global _db_ready
    try:
        from tinydb import TinyDB  # type: ignore

        # Verify database integrity before opening
        from db.backup import verify_database_integrity
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        db_path = DATA_DIR / "nexshield_db.json"

        if db_path.exists():
            verify_database_integrity()

        db = TinyDB(str(db_path), indent=2)
        print(f"   [+] TinyDB database ready: {db_path}")
        _db_ready = True

        # Create startup backup
        try:
            from db.backup import create_backup
            create_backup(label="startup")
        except Exception:
            pass

        return db
    except ImportError:
        print("   [!] TinyDB not installed. Run: pip install tinydb")
        return None
    except Exception as e:
        print(f"   [!] TinyDB initialization failed: {e}")
        return None


def _init_mongodb():
    """Initialize MongoDB as the database backend."""
    global _db_ready, _using_mongodb
    try:
        from pymongo import MongoClient  # type: ignore
        _real_client: Any = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        _real_client.admin.command("ping")
        print(f"   [+] Connected to MongoDB: {MONGO_URI}")
        _db_ready = True
        _using_mongodb = True
        return _real_client
    except ImportError:
        print("   [!] pymongo not installed. Falling back to TinyDB...")
        return None
    except Exception as e:
        print(f"   [!] MongoDB connection failed: {e}")
        print("   [!] Falling back to TinyDB...")
        return None


# ─── Initialize Database ────────────────────────────────────────────
client: Any = None
db: Any = None

if MONGO_URI:
    client = _init_mongodb()
    if client:
        db = client[DB_NAME]

if db is None:
    _tinydb_instance = _init_tinydb()
    if _tinydb_instance is not None:
        db = _tinydb_instance
        client = _tinydb_instance


# ─── Collection References ──────────────────────────────────────────
if _using_mongodb and db is not None:
    network_scans: Any = db["network_scans"]
    threats: Any = db["threats"]
    activity_log: Any = db["activity_log"]
    cve_cache: Any = db["cve_cache"]
    users: Any = db["users"]
    ip_geo_cache: Any = db["ip_geo_cache"]
    scan_jobs: Any = db["scan_jobs"]
elif db is not None:
    from db.tiny_collection import TinyCollection

    network_scans = TinyCollection(db.table("network_scans"), db, name="network_scans")
    threats = TinyCollection(db.table("threats"), db, name="threats")
    activity_log = TinyCollection(db.table("activity_log"), db, name="activity_log")
    cve_cache = TinyCollection(db.table("cve_cache"), db, name="cve_cache")
    users = TinyCollection(db.table("users"), db, name="users")
    ip_geo_cache = TinyCollection(db.table("ip_geo_cache"), db, name="ip_geo_cache")
    scan_jobs = TinyCollection(db.table("scan_jobs"), db, name="scan_jobs")
else:
    class DummyCollection:
        def __getattr__(self, name: str) -> Any:
            def noop(*args: Any, **kwargs: Any) -> None:
                return None
            return noop

    db = DummyCollection()
    network_scans = threats = activity_log = cve_cache = DummyCollection()
    users = ip_geo_cache = scan_jobs = DummyCollection()


# ─── Connection Check ───────────────────────────────────────────────
def check_connection() -> bool:
    """Return True if the database is ready."""
    return _db_ready

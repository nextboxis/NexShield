"""
config.py — Database Configuration for NexShield
=================================================
Supports two backends:
  1. TinyDB (DEFAULT) — Zero-install, file-based JSON database.
     Works out of the box on Windows, Linux, and macOS.
  2. MongoDB (OPTIONAL) — Set MONGO_URI in .env to enable.

Usage in other modules:
    from config import threats, network_scans, activity_log, users, ...
    from config import check_connection
"""

import os
import re
import sys
import time
import uuid
import threading
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timezone

_db_lock = threading.RLock()

# ─── Load .env automatically ────────────────────────────────────────
try:
    from dotenv import load_dotenv  # type: ignore
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
        print("   [+] Loaded .env configuration file.")
    else:
        # Try to auto-create from .env.example
        _example_path = Path(__file__).parent / ".env.example"
        if _example_path.exists():
            import shutil
            shutil.copy2(_example_path, _env_path)
            load_dotenv(_env_path)
            print("   [+] Created .env from .env.example (edit it to customize).")
except ImportError:
    pass  # python-dotenv not installed, rely on system env vars


# ─── Database Selection ─────────────────────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
DB_NAME = os.environ.get("MONGO_DB", "threat_intel")
DATA_DIR = Path(__file__).parent / "data"

_db_ready = False
_using_mongodb = False


# ═════════════════════════════════════════════════════════════════════
#  TinyDB Collection Wrapper — MongoDB-compatible API
# ═════════════════════════════════════════════════════════════════════

class TinyCollection:
    """
    Wraps a TinyDB table to provide a MongoDB-like collection API.
    Supports: find, find_one, insert_one, insert_many, update_many,
    delete_many, count_documents, distinct, aggregate (basic).
    """

    def __init__(self, table, db_instance=None):
        from tinydb import Query  # type: ignore
        self._table = table
        self._db = db_instance
        self._Q = Query

    # ── Insert ───────────────────────────────────────────────────
    def insert_one(self, doc: dict) -> Any:
        """Insert a single document."""
        with _db_lock:
            doc = self._prepare_doc(doc)
            doc_id = self._table.insert(doc)

        class _Result:
            def __init__(self, inserted_id):
                self.inserted_id = inserted_id
        return _Result(doc_id)

    def insert_many(self, docs: list) -> Any:
        """Insert multiple documents."""
        with _db_lock:
            prepared = [self._prepare_doc(d) for d in docs]
            ids = self._table.insert_multiple(prepared)

        class _Result:
            def __init__(self, inserted_ids):
                self.inserted_ids = inserted_ids
        return _Result(ids)

    # ── Find ─────────────────────────────────────────────────────
    def find(self, query: Optional[dict] = None, sort=None, **kwargs) -> '_TinyCursor':
        """Return a cursor-like object over matching documents."""
        with _db_lock:
            docs = self._search(query or {})
        return _TinyCursor(docs, sort)

    def find_one(self, query: Optional[dict] = None, sort=None, **kwargs) -> Optional[dict]:
        """Return the first matching document or None."""
        with _db_lock:
            docs = self._search(query or {})
        if sort:
            docs = _TinyCursor._sort_docs(docs, sort)
        return docs[0] if docs else None

    # ── Update ───────────────────────────────────────────────────
    def update_many(self, query: dict, update: dict) -> Any:
        """Update all documents matching query."""
        with _db_lock:
            docs = self._search(query)
            count = 0
            set_fields = update.get("$set", {})
            
            # Convert datetime objects to ISO strings for JSON storage
            for k, v in set_fields.items():
                if isinstance(v, datetime):
                    set_fields[k] = v.isoformat()
                elif isinstance(v, list):
                    set_fields[k] = [
                        item.isoformat() if isinstance(item, datetime) else item
                        for item in v
                    ]

            for doc in docs:
                doc_id = doc.get("_tinydb_id")
                if doc_id is not None and set_fields:
                    self._table.update(set_fields, doc_ids=[doc_id])
                    count += 1

        class _Result:
            def __init__(self, modified_count):
                self.modified_count = modified_count
        return _Result(count)

    def update_one(self, query: dict, update: dict, upsert: bool = False, **kwargs) -> Any:
        """Update the first document matching query. Supports upsert."""
        with _db_lock:
            docs = self._search(query)
            count = 0
            set_fields = update.get("$set", {})
            
            # Convert datetime objects to ISO strings for JSON storage
            for k, v in set_fields.items():
                if isinstance(v, datetime):
                    set_fields[k] = v.isoformat()
                elif isinstance(v, list):
                    set_fields[k] = [
                        item.isoformat() if isinstance(item, datetime) else item
                        for item in v
                    ]

            if docs and set_fields:
                doc_id = docs[0].get("_tinydb_id")
                if doc_id is not None:
                    self._table.update(set_fields, doc_ids=[doc_id])
                    count = 1
            elif upsert and set_fields:
                # No matching doc found — insert a new one with query fields + set_fields
                new_doc = {}
                for k, v in query.items():
                    if not isinstance(v, dict):  # Skip operators like $regex
                        new_doc[k] = v
                new_doc.update(set_fields)
                new_doc = self._prepare_doc(new_doc)
                self._table.insert(new_doc)
                count = 1

        class _Result:
            def __init__(self, modified_count):
                self.modified_count = modified_count
        return _Result(count)

    # ── Delete ───────────────────────────────────────────────────
    def delete_many(self, query: Optional[dict] = None) -> Any:
        """Delete all matching documents. Empty query = delete all."""
        with _db_lock:
            if not query:
                count = len(self._table)
                self._table.truncate()
            else:
                docs = self._search(query)
                ids = [d["_tinydb_id"] for d in docs if "_tinydb_id" in d]
                self._table.remove(doc_ids=ids)
                count = len(ids)

        class _Result:
            def __init__(self, deleted_count):
                self.deleted_count = deleted_count
        return _Result(count)

    # ── Count & Distinct ─────────────────────────────────────────
    def count_documents(self, query: Optional[dict] = None) -> int:
        """Count matching documents."""
        with _db_lock:
            if not query:
                return len(self._table)
            return len(self._search(query))

    def distinct(self, field: str, query: Optional[dict] = None) -> list:
        """Return distinct values for a field."""
        with _db_lock:
            docs = self._search(query or {})
        seen = set()
        result = []
        for d in docs:
            val = d.get(field)
            if val is not None:
                key = str(val)
                if key not in seen:
                    seen.add(key)
                    result.append(val)
        return result

    # ── Aggregate (basic pipeline support) ───────────────────────
    def aggregate(self, pipeline: list) -> list:
        """
        Basic MongoDB aggregation pipeline support.
        Supports: $match, $group, $sort, $limit, $unwind, $push, $sum,
        $first, $max, $min, $addToSet, $cond.
        """
        with _db_lock:
            docs = list(self._table.all())
        # Add _id field simulation
        for d in docs:
            if "_id" not in d:
                d["_id"] = d.get("_tinydb_id", id(d))

        for stage in pipeline:
            if "$match" in stage:
                docs = [d for d in docs if self._matches_query(d, stage["$match"])]

            elif "$unwind" in stage:
                field = stage["$unwind"]
                if field.startswith("$"):
                    field = field[1:]
                unwound = []
                for d in docs:
                    val = d.get(field, [])
                    if isinstance(val, list):
                        for item in val:
                            new_doc = dict(d)
                            new_doc[field] = item
                            unwound.append(new_doc)
                    else:
                        unwound.append(d)
                docs = unwound

            elif "$group" in stage:
                docs = self._aggregate_group(docs, stage["$group"])

            elif "$sort" in stage:
                sort_spec = stage["$sort"]
                for field, direction in reversed(list(sort_spec.items())):
                    def _sort_key(d: dict) -> Any:
                        return self._get_nested(d, field) or ""
                    docs.sort(key=_sort_key, reverse=(direction == -1))

            elif "$limit" in stage:
                docs = docs[:stage["$limit"]]

        return docs

    # ── Internal Helpers ─────────────────────────────────────────
    def _prepare_doc(self, doc: dict) -> dict:
        """Prepare a document for insertion."""
        doc = dict(doc)  # Copy
        # Generate a string _id if not present (UUID4 for collision safety)
        if "_id" not in doc:
            doc["_id"] = uuid.uuid4().hex[:24]
        # Convert datetime objects to ISO strings for JSON storage
        for k, v in doc.items():
            if isinstance(v, datetime):
                doc[k] = v.isoformat()
            elif isinstance(v, list):
                doc[k] = [
                    item.isoformat() if isinstance(item, datetime) else item
                    for item in v
                ]
        return doc

    def _search(self, query: dict) -> list:
        """Search documents matching a MongoDB-style query."""
        if not query:
            docs = self._table.all()
        else:
            docs = [d for d in self._table.all() if self._matches_query(d, query)]

        # Add TinyDB doc_id for update/delete operations
        result = []
        for d in docs:
            doc = dict(d)
            doc["_tinydb_id"] = d.doc_id
            if "_id" not in doc:
                doc["_id"] = str(d.doc_id)
            result.append(doc)
        return result

    def _matches_query(self, doc: dict, query: dict) -> bool:
        """Check if a document matches a MongoDB-style query."""
        for key, condition in query.items():
            if key == "$and":
                return all(self._matches_query(doc, q) for q in condition)
            if key == "$or":
                return any(self._matches_query(doc, q) for q in condition)

            val = self._get_nested(doc, key)

            if isinstance(condition, dict):
                for op, operand in condition.items():
                    if op == "$in":
                        if val not in operand:
                            return False
                    elif op == "$nin":
                        if val in operand:
                            return False
                    elif op == "$ne":
                        if val == operand:
                            return False
                    elif op == "$gt":
                        if val is None or val <= operand:
                            return False
                    elif op == "$gte":
                        try:
                            if val is None or val < operand:
                                return False
                        except TypeError:
                            # Handle datetime comparison with string
                            if isinstance(operand, datetime) and isinstance(val, str):
                                try:
                                    val_dt = datetime.fromisoformat(val)
                                    if val_dt < operand:
                                        return False
                                except (ValueError, TypeError):
                                    return False
                            else:
                                return False
                    elif op == "$lt":
                        if val is None or val >= operand:
                            return False
                    elif op == "$lte":
                        if val is None or val > operand:
                            return False
                    elif op == "$regex":
                        flags = 0
                        if condition.get("$options", "") == "i":
                            flags = re.IGNORECASE
                        if val is None or not re.search(operand, str(val), flags):
                            return False
                    elif op == "$exists":
                        if operand and key not in doc:
                            return False
                        if not operand and key in doc:
                            return False
            else:
                # Direct equality
                if val != condition:
                    return False
        return True

    def _get_nested(self, doc: dict, key: str) -> Any:
        """Get a nested field value using dot notation."""
        parts = key.split(".")
        val: Any = doc
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                return None
        return val

    def _aggregate_group(self, docs: list, group_spec: dict) -> list:
        """Handle $group aggregation stage."""
        group_key = group_spec["_id"]
        accumulators = {k: v for k, v in group_spec.items() if k != "_id"}

        groups: dict = {}
        for doc in docs:
            # Resolve group key
            if isinstance(group_key, dict):
                key_val = tuple(
                    (k, self._resolve_field(doc, v))
                    for k, v in group_key.items()
                )
                key_display = {k: self._resolve_field(doc, v) for k, v in group_key.items()}
            elif isinstance(group_key, str) and group_key.startswith("$"):
                key_val = doc.get(group_key[1:])
                key_display = key_val
            else:
                key_val = group_key
                key_display = group_key

            hashable_key = str(key_val)
            if hashable_key not in groups:
                groups[hashable_key] = {"_id": key_display, "_docs": []}
            groups[hashable_key]["_docs"].append(doc)

        # Apply accumulators
        results = []
        for key, group in groups.items():
            result = {"_id": group["_id"]}
            group_docs = group["_docs"]
            for acc_name, acc_spec in accumulators.items():
                if isinstance(acc_spec, dict):
                    op = list(acc_spec.keys())[0]
                    operand = acc_spec[op]

                    if op == "$sum":
                        if isinstance(operand, dict) and "$cond" in operand:
                            # Handle $cond inside $sum
                            cond = operand["$cond"]
                            total = 0
                            for d in group_docs:
                                if isinstance(cond, list) and len(cond) == 3:
                                    test, true_val, false_val = cond
                                    if isinstance(test, dict) and "$eq" in test:
                                        eq_vals = test["$eq"]
                                        field_val = self._resolve_field(d, eq_vals[0])
                                        compare_val = self._resolve_field(d, eq_vals[1]) if isinstance(eq_vals[1], str) and eq_vals[1].startswith("$") else eq_vals[1]
                                        total += true_val if field_val == compare_val else false_val
                            result[acc_name] = total
                        elif operand == 1:
                            result[acc_name] = len(group_docs)
                        elif isinstance(operand, str) and operand.startswith("$"):
                            result[acc_name] = sum(
                                self._resolve_field(d, operand) or 0
                                for d in group_docs
                            )
                        else:
                            result[acc_name] = len(group_docs)

                    elif op == "$first":
                        result[acc_name] = self._resolve_field(
                            group_docs[0], operand
                        ) if group_docs else None

                    elif op == "$max":
                        vals = [self._resolve_field(d, operand) for d in group_docs]
                        vals = [v for v in vals if v is not None]
                        result[acc_name] = max(vals) if vals else None

                    elif op == "$min":
                        vals = [self._resolve_field(d, operand) for d in group_docs]
                        vals = [v for v in vals if v is not None]
                        result[acc_name] = min(vals) if vals else None

                    elif op == "$addToSet":
                        _set_vals: set[Any] = set()
                        for d in group_docs:
                            v = self._resolve_field(d, operand)
                            if v is not None:
                                _set_vals.add(v)
                        result[acc_name] = list(_set_vals)

                    elif op == "$push":
                        if isinstance(operand, dict):
                            pushed = []
                            for d in group_docs:
                                item = {}
                                for field_name, field_ref in operand.items():
                                    item[field_name] = self._resolve_field(d, field_ref)
                                pushed.append(item)
                            result[acc_name] = pushed
                        else:
                            result[acc_name] = [
                                self._resolve_field(d, operand)
                                for d in group_docs
                            ]
                else:
                    result[acc_name] = acc_spec
            results.append(result)
        return results

    def _resolve_field(self, doc: dict, ref) -> Any:
        """Resolve a field reference like '$fieldname' or a literal."""
        if isinstance(ref, str) and ref.startswith("$"):
            return self._get_nested(doc, ref[1:])
        return ref


class _TinyCursor:
    """Cursor-like wrapper for TinyDB query results."""

    def __init__(self, docs: list, sort_spec=None):
        self._docs = list(docs)
        if sort_spec:
            if isinstance(sort_spec, list):
                # MongoDB-style: [("field", direction)]
                for field, direction in reversed(sort_spec):
                    self._docs = self._sort_docs(self._docs, [(field, direction)])
            elif isinstance(sort_spec, str):
                self._docs = self._sort_docs(self._docs, [(sort_spec, 1)])

    def sort(self, field: str, direction: int = 1) -> '_TinyCursor':
        """Sort results by a field."""
        self._docs = self._sort_docs(self._docs, [(field, direction)])
        return self

    def limit(self, n: int) -> '_TinyCursor':
        """Limit results."""
        self._docs = self._docs[:n]
        return self

    @staticmethod
    def _sort_docs(docs: list, sort_spec: list) -> list:
        """Sort docs by MongoDB-style sort spec."""
        for field, direction in reversed(sort_spec):
            def _sort_key(d: dict) -> Any:
                return d.get(field) or ""
            docs.sort(key=_sort_key, reverse=(direction == -1))
        return docs

    def __iter__(self):
        return iter(self._docs)

    def __len__(self):
        return len(self._docs)

    def __list__(self):
        return list(self._docs)


# ═════════════════════════════════════════════════════════════════════
#  Database Initialization
# ═════════════════════════════════════════════════════════════════════

def _init_tinydb():
    """Initialize TinyDB as the database backend."""
    global _db_ready
    try:
        from tinydb import TinyDB  # type: ignore
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        db_path = DATA_DIR / "nexshield_db.json"
        db = TinyDB(str(db_path), indent=2)
        print(f"   [+] TinyDB database ready: {db_path}")
        _db_ready = True
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
        print("   [!] pymongo not installed. Run: pip install pymongo")
        print("   [!] Falling back to TinyDB...")
        return None
    except Exception as e:
        print(f"   [!] MongoDB connection failed: {e}")
        print("   [!] Falling back to TinyDB...")
        return None


# ─── Initialize Database ────────────────────────────────────────────
client: Any = None
db: Any = None

if MONGO_URI:
    # User explicitly wants MongoDB
    client = _init_mongodb()
    if client:
        db = client[DB_NAME]

if db is None:
    # Default: TinyDB
    _tinydb_instance = _init_tinydb()
    if _tinydb_instance is not None:
        db = _tinydb_instance
        client = _tinydb_instance  # For compatibility

# ─── Collection References ──────────────────────────────────────────
if _using_mongodb and db is not None:
    # Direct MongoDB collections
    network_scans: Any = db["network_scans"]
    threats: Any = db["threats"]
    activity_log: Any = db["activity_log"]
    cve_cache: Any = db["cve_cache"]
    users: Any = db["users"]
    ip_geo_cache: Any = db["ip_geo_cache"]
    scan_jobs: Any = db["scan_jobs"]
elif db is not None:
    # TinyDB wrapped collections
    network_scans = TinyCollection(db.table("network_scans"), db)
    threats = TinyCollection(db.table("threats"), db)
    activity_log = TinyCollection(db.table("activity_log"), db)
    cve_cache = TinyCollection(db.table("cve_cache"), db)
    users = TinyCollection(db.table("users"), db)
    ip_geo_cache = TinyCollection(db.table("ip_geo_cache"), db)
    scan_jobs = TinyCollection(db.table("scan_jobs"), db)
else:
    # Fallback: dummy objects to prevent import errors
    class DummyCollection:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None
    db = DummyCollection()
    network_scans = threats = activity_log = cve_cache = DummyCollection()
    users = ip_geo_cache = scan_jobs = DummyCollection()


# ─── Connection Check ────────────────────────────────────────────────
def check_connection() -> bool:
    """Return True if the database is ready."""
    return _db_ready

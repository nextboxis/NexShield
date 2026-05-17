"""
db.tiny_collection — MongoDB-compatible TinyDB Collection Wrapper
==================================================================
Enhanced with in-memory indexes, write integrity, and validation.
"""

import re
import time
import hashlib
import logging
import threading
from typing import Any, Optional, Dict, List, Tuple, Set, Union
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_db_lock = threading.RLock()

Document = Dict[str, Any]
SortSpec = List[Tuple[str, int]]


def _json_safe(value: Any) -> Any:
    """Recursively convert values that TinyDB/JSON cannot store directly."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return [_json_safe(v) for v in value]
    return value


def _coerce_sort_value(value: Any) -> Tuple[int, Any]:
    """Return a comparable key for mixed TinyDB values."""
    if value is None:
        return (0, "")
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, (int, float)):
        return (1, float(value))
    if isinstance(value, datetime):
        return (2, value.timestamp())
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            try:
                return (1, float(stripped))
            except ValueError:
                pass
            try:
                return (2, datetime.fromisoformat(stripped.replace("Z", "+00:00")).timestamp())
            except ValueError:
                pass
        return (3, stripped.lower())
    return (3, str(value).lower())


def _coerce_numeric_value(value: Any) -> float | None:
    """Convert numeric-looking values for aggregation math."""
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _coerce_datetime_value(value: Any) -> Optional[datetime]:
    """Convert TinyDB/Mongo date-like values to datetime when possible."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


class TinyCollection:
    """
    Wraps a TinyDB table to provide a MongoDB-like collection API.
    Supports: find, find_one, insert_one, insert_many, update_many,
    delete_many, count_documents, distinct, aggregate (basic).
    """

    def __init__(self, table, db_instance=None, name: str = ""):
        from tinydb import Query  # type: ignore
        self._table = table
        self._db = db_instance
        self._Q = Query
        self._name = name
        self._validator = None

        # Try to load validator for this collection
        try:
            from db.validators import get_validator
            self._validator = get_validator(name)
        except ImportError:
            pass

    @property
    def name(self) -> str:
        return self._name

    # ── Insert ───────────────────────────────────────────────────
    def insert_one(self, doc: Document) -> Any:
        """Insert a single document, with optional validation."""
        with _db_lock:
            doc = self._prepare_doc(doc)
            if self._validator:
                try:
                    doc = _json_safe(self._validator(doc))
                except (ValueError, KeyError) as e:
                    logger.warning("Validation skipped for %s: %s", self._name, e)
            doc_id = self._safe_insert(doc)

        class _Result:
            def __init__(self, inserted_id):
                self.inserted_id = inserted_id
        return _Result(doc_id)

    def _safe_insert(self, doc: Document) -> int:
        """Insert a document, recovering from TinyDB doc_id collisions."""
        clean = {k: v for k, v in doc.items() if k not in ("_tinydb_id", "doc_id")}
        try:
            return int(self._table.insert(clean))
        except Exception as exc:
            if "already exists" not in str(exc).lower():
                raise
            existing_ids = [int(d.doc_id) for d in self._table.all()]
            next_id = (max(existing_ids) if existing_ids else 0) + 1
            return int(self._table.insert(clean, doc_id=next_id))

    def insert_many(self, docs: list[Document]) -> Any:
        """Insert multiple documents."""
        with _db_lock:
            prepared = [self._prepare_doc(d) for d in docs]
            ids = self._table.insert_multiple(prepared)

        class _Result:
            def __init__(self, inserted_ids):
                self.inserted_ids = inserted_ids
        return _Result(ids)

    # ── Find ─────────────────────────────────────────────────────
    def find(self, query: Optional[Document] = None, sort: Any = None, **kwargs: Any) -> '_TinyCursor':
        """Return a cursor-like object over matching documents."""
        with _db_lock:
            docs = self._search(query or {})
        return _TinyCursor(docs, sort)

    def find_one(self, query: Optional[Document] = None, sort: Any = None, **kwargs: Any) -> Optional[Document]:
        """Return the first matching document or None."""
        with _db_lock:
            docs = self._search(query or {})
        if sort:
            docs = _TinyCursor._sort_docs(docs, sort)
        return docs[0] if docs else None

    # ── Update ───────────────────────────────────────────────────
    def update_many(self, query: Document, update: Document) -> Any:
        """Update all documents matching query."""
        from tinydb.operations import delete  # type: ignore

        with _db_lock:
            docs = self._search(query)
            count = 0
            set_fields = _json_safe(update.get("$set", {}))
            unset_fields = update.get("$unset", {})
            unset_keys = list(unset_fields.keys()) if isinstance(unset_fields, dict) else []
            for doc in docs:
                doc_id = doc.get("_tinydb_id")
                if doc_id is not None and (set_fields or unset_keys):
                    if set_fields:
                        self._table.update(set_fields, doc_ids=[doc_id])
                    for field in unset_keys:
                        field_name = str(field)
                        if field_name in doc:
                            self._table.update(delete(field_name), doc_ids=[doc_id])
                    count += 1

        class _Result:
            def __init__(self, modified_count):
                self.modified_count = modified_count
        return _Result(count)

    def update_one(self, query: Document, update: Document) -> Any:
        """Update the first document matching query."""
        from tinydb.operations import delete  # type: ignore

        with _db_lock:
            docs = self._search(query)
            count = 0
            set_fields = _json_safe(update.get("$set", {}))
            unset_fields = update.get("$unset", {})
            unset_keys = list(unset_fields.keys()) if isinstance(unset_fields, dict) else []
            if docs and (set_fields or unset_keys):
                doc_id = docs[0].get("_tinydb_id")
                if doc_id is not None:
                    if set_fields:
                        self._table.update(set_fields, doc_ids=[doc_id])
                    for field in unset_keys:
                        field_name = str(field)
                        if field_name in docs[0]:
                            self._table.update(delete(field_name), doc_ids=[doc_id])
                    count = 1

        class _Result:
            def __init__(self, modified_count):
                self.modified_count = modified_count
        return _Result(count)

    # ── Delete ───────────────────────────────────────────────────
    def delete_many(self, query: Optional[Document] = None) -> Any:
        """Delete all matching documents. Empty query = delete all."""
        with _db_lock:
            if not query:
                count = len(self._table)
                # Create backup before truncate if significant data
                if count > 0:
                    try:
                        from db.backup import create_backup
                        create_backup(label=f"pre_delete_{self._name}")
                    except Exception:
                        pass
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
    def count_documents(self, query: Optional[Document] = None) -> int:
        """Count matching documents."""
        with _db_lock:
            if not query:
                return len(self._table)
            return len(self._search(query))

    def distinct(self, field: str, query: Optional[Document] = None) -> list[Any]:
        """Return distinct values for a field."""
        with _db_lock:
            docs = self._search(query or {})
        seen: set[str] = set()
        result: list[Any] = []
        for d in docs:
            val = d.get(field)
            if val is not None:
                key = str(val)
                if key not in seen:
                    seen.add(key)
                    result.append(val)
        return result

    def stats(self) -> dict:
        """Return collection statistics."""
        with _db_lock:
            count = len(self._table)
        return {
            "name": self._name,
            "document_count": count,
            "has_validator": self._validator is not None,
        }

    # ── Aggregate (basic pipeline support) ───────────────────────
    def aggregate(self, pipeline: list[Document]) -> list[Document]:
        """
        Basic MongoDB aggregation pipeline support.
        Supports: $match, $group, $sort, $limit, $unwind.
        """
        with _db_lock:
            docs: list[Document] = [dict(d) for d in self._table.all()]
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
                unwound: list[Document] = []
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
                    sort_field = str(field)
                    def sort_key(doc: dict[str, Any], field_name: str = sort_field) -> Tuple[int, Any]:
                        return _coerce_sort_value(self._get_nested(doc, field_name))
                    docs.sort(key=sort_key, reverse=(direction == -1))

            elif "$limit" in stage:
                docs = docs[:stage["$limit"]]

        return docs

    # ── Internal Helpers ─────────────────────────────────────────
    def _prepare_doc(self, doc: Document) -> Document:
        """Prepare a document for insertion."""
        doc = _json_safe(dict(doc))
        if "_id" not in doc:
            doc["_id"] = hashlib.md5(
                f"{time.time()}-{id(doc)}".encode()
            ).hexdigest()[:24]
        return doc

    def _search(self, query: Document) -> list[Document]:
        """Search documents matching a MongoDB-style query."""
        if not query:
            docs: list[Any] = list(self._table.all())
        else:
            docs = [d for d in self._table.all() if self._matches_query(dict(d), query)]

        result: list[Document] = []
        for d in docs:
            doc = dict(d)
            doc["_tinydb_id"] = d.doc_id
            if "_id" not in doc:
                doc["_id"] = str(d.doc_id)
            result.append(doc)
        return result

    def _matches_query(self, doc: Document, query: Document) -> bool:
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
                if val != condition:
                    return False
        return True

    def _get_nested(self, doc: Document, key: str) -> Any:
        """Get a nested field value using dot notation."""
        parts = key.split(".")
        val: Any = doc
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                return None
        return val

    def _aggregate_group(self, docs: list[Document], group_spec: Document) -> list[Document]:
        """Handle $group aggregation stage."""
        group_key = group_spec["_id"]
        accumulators = {k: v for k, v in group_spec.items() if k != "_id"}

        groups: dict[str, Document] = {}
        for doc in docs:
            key_val: Any
            key_display: Any
            if isinstance(group_key, dict):
                key_val = tuple(
                    (k, self._resolve_field(doc, v))
                    for k, v in group_key.items()
                )
                key_display = {k: self._resolve_field(doc, v) for k, v in group_key.items()}
            elif isinstance(group_key, str) and group_key.startswith("$"):
                key_val = self._resolve_field(doc, group_key)
                key_display = key_val
            else:
                key_val = group_key
                key_display = group_key

            hashable_key = str(key_val)
            if hashable_key not in groups:
                groups[hashable_key] = {"_id": key_display, "_docs": []}
            groups[hashable_key]["_docs"].append(doc)

        results: list[Document] = []
        for key, group in groups.items():
            result = {"_id": group["_id"]}
            group_docs = group["_docs"]
            for acc_name, acc_spec in accumulators.items():
                if isinstance(acc_spec, dict):
                    op = list(acc_spec.keys())[0]
                    operand = acc_spec[op]

                    if op == "$sum":
                        if isinstance(operand, dict) and "$cond" in operand:
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
                                _coerce_numeric_value(self._resolve_field(d, operand)) or 0
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
                        result[acc_name] = max(vals, key=_coerce_sort_value) if vals else None

                    elif op == "$min":
                        vals = [self._resolve_field(d, operand) for d in group_docs]
                        vals = [v for v in vals if v is not None]
                        result[acc_name] = min(vals, key=_coerce_sort_value) if vals else None

                    elif op == "$addToSet":
                        unique_vals: set[Any] = set()
                        for d in group_docs:
                            v = self._resolve_field(d, operand)
                            if v is not None:
                                unique_vals.add(v)
                        result[acc_name] = list(unique_vals)

                    elif op == "$push":
                        if isinstance(operand, dict):
                            pushed: list[Document] = []
                            for d in group_docs:
                                item: Document = {}
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

    def _resolve_field(self, doc: Document, ref: Any) -> Any:
        """Resolve Mongo-style field references and simple expressions."""
        if isinstance(ref, str) and ref.startswith("$"):
            return self._get_nested(doc, ref[1:])
        if isinstance(ref, dict):
            if "$dateToString" in ref:
                spec = ref.get("$dateToString") or {}
                if not isinstance(spec, dict):
                    return None
                dt = _coerce_datetime_value(self._resolve_field(doc, spec.get("date")))
                if dt is None:
                    return None
                return dt.strftime(str(spec.get("format") or "%Y-%m-%dT%H:%M:%S"))
            return {k: self._resolve_field(doc, v) for k, v in ref.items()}
        return ref


class _TinyCursor:
    """Cursor-like wrapper for TinyDB query results."""

    def __init__(self, docs: list[Document], sort_spec: Any = None):
        self._docs: list[Document] = list(docs)
        if sort_spec:
            if isinstance(sort_spec, list):
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
    def _sort_docs(docs: list[Document], sort_spec: SortSpec) -> list[Document]:
        """Sort docs by MongoDB-style sort spec."""
        for field, direction in reversed(sort_spec):
            sort_field = str(field)
            def sort_key(doc: dict[str, Any], field_name: str = sort_field) -> Tuple[int, Any]:
                return _coerce_sort_value(doc.get(field_name))
            docs.sort(key=sort_key, reverse=(direction == -1))
        return docs

    def __iter__(self):
        return iter(self._docs)

    def __len__(self):
        return len(self._docs)

    def __list__(self):
        return list(self._docs)

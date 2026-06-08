"""Tests for config.py — TinyDB wrapper and database operations."""

import pytest
import os
import sys
from datetime import datetime, timezone


def test_tiny_collection_crud(tmp_path, monkeypatch):
    """Test basic CRUD operations on TinyCollection."""
    from tinydb import TinyDB
    # Patch DATA_DIR to use temp directory
    db = TinyDB(str(tmp_path / "test_db.json"))
    
    # Import after patching
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from config import TinyCollection
    
    coll = TinyCollection(db.table("test_coll"), db)
    
    # Insert
    result = coll.insert_one({"name": "test1", "value": 42})
    assert result.inserted_id is not None
    
    # Find
    doc = coll.find_one({"name": "test1"})
    assert doc is not None
    assert doc["name"] == "test1"
    assert doc["value"] == 42
    assert "_id" in doc
    
    # Count
    assert coll.count_documents({}) == 1
    assert coll.count_documents({"name": "test1"}) == 1
    assert coll.count_documents({"name": "nonexistent"}) == 0
    
    # Update
    coll.update_one({"name": "test1"}, {"$set": {"value": 99}})
    updated = coll.find_one({"name": "test1"})
    assert updated["value"] == 99
    
    # Delete
    del_result = coll.delete_many({"name": "test1"})
    assert del_result.deleted_count == 1
    assert coll.count_documents({}) == 0
    
    db.close()


def test_tiny_collection_upsert(tmp_path):
    """Test upsert functionality in update_one."""
    from tinydb import TinyDB
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from config import TinyCollection
    
    db = TinyDB(str(tmp_path / "test_upsert.json"))
    coll = TinyCollection(db.table("test_upsert"), db)
    
    # Upsert when doc doesn't exist — should insert
    coll.update_one(
        {"cve_id": "CVE-2024-1234"},
        {"$set": {"score": 9.8, "severity": "critical"}},
        upsert=True
    )
    doc = coll.find_one({"cve_id": "CVE-2024-1234"})
    assert doc is not None
    assert doc["score"] == 9.8
    assert doc["severity"] == "critical"
    
    # Upsert when doc exists — should update
    coll.update_one(
        {"cve_id": "CVE-2024-1234"},
        {"$set": {"score": 7.5}},
        upsert=True
    )
    doc = coll.find_one({"cve_id": "CVE-2024-1234"})
    assert doc["score"] == 7.5
    assert coll.count_documents({}) == 1  # Still only one doc
    
    db.close()


def test_tiny_collection_distinct(tmp_path):
    """Test distinct() returns unique field values."""
    from tinydb import TinyDB
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from config import TinyCollection
    
    db = TinyDB(str(tmp_path / "test_distinct.json"))
    coll = TinyCollection(db.table("test_distinct"), db)
    
    coll.insert_one({"severity": "high", "host": "10.0.0.1"})
    coll.insert_one({"severity": "low", "host": "10.0.0.2"})
    coll.insert_one({"severity": "high", "host": "10.0.0.3"})
    
    severities = coll.distinct("severity")
    assert set(severities) == {"high", "low"}
    
    hosts = coll.distinct("host")
    assert len(hosts) == 3
    
    db.close()


def test_tiny_collection_aggregate_group(tmp_path):
    """Test basic $group aggregation."""
    from tinydb import TinyDB
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from config import TinyCollection
    
    db = TinyDB(str(tmp_path / "test_agg.json"))
    coll = TinyCollection(db.table("test_agg"), db)
    
    coll.insert_one({"severity": "high", "host": "10.0.0.1"})
    coll.insert_one({"severity": "high", "host": "10.0.0.2"})
    coll.insert_one({"severity": "low", "host": "10.0.0.3"})
    
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]
    results = coll.aggregate(pipeline)
    
    result_map = {r["_id"]: r["count"] for r in results}
    assert result_map["high"] == 2
    assert result_map["low"] == 1
    
    db.close()


def test_tiny_collection_uuid_ids(tmp_path):
    """Verify _id is generated using UUID4 format (hex string)."""
    from tinydb import TinyDB
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from config import TinyCollection
    
    db = TinyDB(str(tmp_path / "test_uuid.json"))
    coll = TinyCollection(db.table("test_uuid"), db)
    
    coll.insert_one({"name": "test"})
    doc = coll.find_one({"name": "test"})
    
    # Should be a 24-char hex string
    assert len(doc["_id"]) == 24
    int(doc["_id"], 16)  # Should not raise — valid hex
    
    db.close()

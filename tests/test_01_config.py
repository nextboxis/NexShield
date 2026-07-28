"""
test_config.py — Unit tests for TinyCollection database operations
"""

import os
import shutil
import tempfile
import pytest
from tinydb import TinyDB
from config import TinyCollection


@pytest.fixture
def temp_tiny_col():
    """Create a temporary TinyCollection instance backed by a temporary file."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_db.json")
    db = TinyDB(db_path)
    table = db.table("test_table")
    col = TinyCollection(table, db_instance=db)
    yield col
    db.close()
    shutil.rmtree(temp_dir)


def test_tiny_collection_crud(temp_tiny_col):
    # Insert
    res = temp_tiny_col.insert_one({"name": "Item A", "severity": "high", "ip": "10.0.0.1"})
    assert res.inserted_id is not None

    # Count
    count = temp_tiny_col.count_documents({"ip": "10.0.0.1"})
    assert count == 1

    # Find one
    doc = temp_tiny_col.find_one({"name": "Item A"})
    assert doc is not None
    assert doc["severity"] == "high"

    # Find list
    items = list(temp_tiny_col.find({"ip": "10.0.0.1"}))
    assert len(items) == 1

    # Update
    temp_tiny_col.update_many({"ip": "10.0.0.1"}, {"$set": {"severity": "critical"}})
    updated_doc = temp_tiny_col.find_one({"ip": "10.0.0.1"})
    assert updated_doc["severity"] == "critical"

    # Delete
    temp_tiny_col.delete_many({"ip": "10.0.0.1"})
    assert temp_tiny_col.count_documents({"ip": "10.0.0.1"}) == 0

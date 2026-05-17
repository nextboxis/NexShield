"""
config.py — Backward-Compatible Re-export Layer
=================================================
This module now re-exports all database objects from the new `db` package.
Existing imports like `from config import threats` continue to work.

The actual database logic lives in:
  - db/engine.py       — Initialization (TinyDB/MongoDB selection)
  - db/tiny_collection.py — MongoDB-compatible TinyDB wrapper
  - db/backup.py       — Backup/restore utilities
  - db/validators.py   — Schema validation
"""

# Re-export everything from the db package for backward compatibility
from db import (
    threats,
    network_scans,
    activity_log,
    cve_cache,
    users,
    ip_geo_cache,
    scan_jobs,
    check_connection,
    db,
    client,
    create_backup,
    restore_backup,
    auto_cleanup_backups,
)

__all__ = [
    "threats",
    "network_scans",
    "activity_log",
    "cve_cache",
    "users",
    "ip_geo_cache",
    "scan_jobs",
    "check_connection",
    "db",
    "client",
    "create_backup",
    "restore_backup",
    "auto_cleanup_backups",
]

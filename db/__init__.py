"""
db — NexShield Database Package
================================
Provides a clean, modular database layer with MongoDB-compatible API.
Supports TinyDB (default, zero-install) and MongoDB (optional).

Usage:
    from db import threats, network_scans, activity_log, users
    from db import cve_cache, ip_geo_cache, scan_jobs
    from db import check_connection, create_backup, restore_backup
"""

from db.engine import (
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
)

from db.backup import create_backup, restore_backup, auto_cleanup_backups

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

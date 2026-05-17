"""
db.backup — Database Backup & Recovery for NexShield
=====================================================
Provides automatic backup, restore, and corruption-recovery utilities
for the TinyDB JSON database.

Features:
  - Timestamped backups in data/backups/
  - Auto-cleanup: keeps only the last 5 backups
  - Corruption detection and auto-restore on startup
  - Pre-destructive-operation snapshots
"""

import json
import shutil
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Paths ──────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent.parent / "data"
DB_PATH = DATA_DIR / "nexshield_db.json"
BACKUP_DIR = DATA_DIR / "backups"
MAX_BACKUPS = 5


def _ensure_backup_dir() -> Path:
    """Ensure the backup directory exists."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return BACKUP_DIR


def create_backup(label: str = "auto") -> Optional[Path]:
    """
    Create a timestamped backup of the database file.

    Args:
        label: A short label to include in the backup filename.

    Returns:
        Path to the backup file, or None if backup failed.
    """
    if not DB_PATH.exists():
        logger.warning("Cannot backup: database file does not exist at %s", DB_PATH)
        return None

    # Don't backup empty or trivially small files
    if DB_PATH.stat().st_size < 3:
        logger.info("Skipping backup: database file is empty or trivial.")
        return None

    try:
        _ensure_backup_dir()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_name = f"nexshield_db_{label}_{timestamp}.json"
        backup_path = BACKUP_DIR / backup_name

        shutil.copy2(str(DB_PATH), str(backup_path))
        logger.info("Database backup created: %s", backup_path.name)

        # Auto-cleanup old backups
        auto_cleanup_backups()

        return backup_path

    except Exception as e:
        logger.error("Failed to create database backup: %s", e)
        return None


def restore_backup(backup_path: Optional[Path] = None) -> bool:
    """
    Restore the database from a backup file.

    Args:
        backup_path: Path to the backup file. If None, uses the most recent backup.

    Returns:
        True if restore succeeded, False otherwise.
    """
    try:
        if backup_path is None:
            backup_path = get_latest_backup()

        if backup_path is None or not backup_path.exists():
            logger.error("No backup file available for restore.")
            return False

        # Validate the backup file is valid JSON
        with open(backup_path, "r", encoding="utf-8") as f:
            json.load(f)  # Will raise if invalid

        shutil.copy2(str(backup_path), str(DB_PATH))
        logger.info("Database restored from backup: %s", backup_path.name)
        return True

    except json.JSONDecodeError as e:
        logger.error("Backup file is corrupted (invalid JSON): %s — %s", backup_path, e)
        return False
    except Exception as e:
        logger.error("Failed to restore database from backup: %s", e)
        return False


def get_latest_backup() -> Optional[Path]:
    """Return the most recent backup file path, or None if no backups exist."""
    if not BACKUP_DIR.exists():
        return None

    backups = sorted(
        BACKUP_DIR.glob("nexshield_db_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return backups[0] if backups else None


def auto_cleanup_backups() -> int:
    """
    Remove old backups, keeping only the most recent MAX_BACKUPS.

    Returns:
        Number of backups removed.
    """
    if not BACKUP_DIR.exists():
        return 0

    backups = sorted(
        BACKUP_DIR.glob("nexshield_db_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    removed = 0
    for old_backup in backups[MAX_BACKUPS:]:
        try:
            old_backup.unlink()
            removed += 1
            logger.debug("Removed old backup: %s", old_backup.name)
        except Exception as e:
            logger.warning("Failed to remove old backup %s: %s", old_backup.name, e)

    if removed:
        logger.info("Cleaned up %d old backup(s), keeping %d most recent.", removed, MAX_BACKUPS)

    return removed


def verify_database_integrity() -> bool:
    """
    Check if the database file is valid JSON.
    If corrupted, attempt auto-recovery from the latest backup.

    Returns:
        True if the database is healthy (or was recovered), False if unrecoverable.
    """
    if not DB_PATH.exists():
        logger.info("No database file found. A fresh one will be created.")
        return True  # TinyDB will create it

    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            logger.warning("Database file is empty. Will be re-initialized.")
            return True

        json.load(open(DB_PATH, "r", encoding="utf-8"))
        logger.info("Database integrity check passed.")
        return True

    except json.JSONDecodeError as e:
        logger.error("DATABASE CORRUPTION DETECTED: %s", e)
        logger.info("Attempting auto-recovery from latest backup...")

        if restore_backup():
            logger.info("Auto-recovery succeeded!")
            return True
        else:
            logger.warning("No valid backup available. Resetting database to empty state.")
            try:
                # Save the corrupted file for forensics
                corrupted_path = DATA_DIR / f"nexshield_db_CORRUPTED_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                shutil.move(str(DB_PATH), str(corrupted_path))
                logger.info("Corrupted file saved to: %s", corrupted_path.name)

                # Create fresh empty database
                with open(DB_PATH, "w", encoding="utf-8") as f:
                    json.dump({}, f)
                logger.info("Fresh database created.")
                return True

            except Exception as reset_err:
                logger.critical("Failed to reset corrupted database: %s", reset_err)
                return False

    except Exception as e:
        logger.error("Unexpected error during integrity check: %s", e)
        return False


def list_backups() -> list[dict]:
    """
    Return a list of available backups with metadata.

    Returns:
        List of dicts with 'filename', 'path', 'size_kb', 'created_at'.
    """
    if not BACKUP_DIR.exists():
        return []

    backups = sorted(
        BACKUP_DIR.glob("nexshield_db_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    result = []
    for b in backups:
        stat = b.stat()
        result.append({
            "filename": b.name,
            "path": str(b),
            "size_kb": round(stat.st_size / 1024, 1),
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })

    return result

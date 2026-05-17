"""
db.validators — Schema Validation for NexShield Collections
=============================================================
Ensures data integrity by validating documents before insertion.
Each validator normalizes the document and returns a clean copy.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

Document = dict[str, Any]


def validate_threat(doc: Document) -> Document:
    """
    Validate and normalize a threat document.

    Required fields: name, severity, host
    Auto-populated: detected_at, _validated
    """
    clean = dict(doc)

    # Required fields
    name = (clean.get("name") or "").strip()
    if not name:
        raise ValueError("Threat document requires a 'name' field.")

    severity = (clean.get("severity") or "").strip().lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "medium"  # Default to medium if invalid

    host = (clean.get("host") or "").strip()
    if not host:
        raise ValueError("Threat document requires a 'host' field.")

    clean["name"] = name
    clean["severity"] = severity
    clean["host"] = host

    # Auto-populate timestamp if missing
    if "detected_at" not in clean or clean["detected_at"] is None:
        clean["detected_at"] = datetime.now(timezone.utc)

    # Ensure optional fields have defaults
    clean.setdefault("cve_id", "")
    clean.setdefault("source", "unknown")
    clean.setdefault("detail", "")
    clean.setdefault("tags", [])
    clean.setdefault("quarantined", False)
    clean["_validated"] = True

    return clean


def validate_scan(doc: Document) -> Document:
    """
    Validate and normalize a network scan document.

    Required fields: host
    Auto-populated: scanned_at, _validated
    """
    clean = dict(doc)

    host = (clean.get("host") or "").strip()
    if not host:
        raise ValueError("Scan document requires a 'host' field.")

    clean["host"] = host

    # Auto-populate timestamp if missing
    if "scanned_at" not in clean or clean["scanned_at"] is None:
        clean["scanned_at"] = datetime.now(timezone.utc)

    # Defaults
    clean.setdefault("scan_type", "default")
    clean.setdefault("open_port_count", 0)
    clean.setdefault("services_detected", [])
    clean.setdefault("state", "up")
    clean["_validated"] = True

    return clean


def validate_user(doc: Document) -> Document:
    """
    Validate and normalize a user document.

    Required fields: username, password_hash
    Auto-populated: created_at, role, _validated
    """
    clean = dict(doc)

    username = (clean.get("username") or "").strip()
    if not username or len(username) < 3:
        raise ValueError("User document requires a 'username' field (min 3 characters).")

    password_hash = (clean.get("password_hash") or "").strip()
    if not password_hash:
        raise ValueError("User document requires a 'password_hash' field.")

    clean["username"] = username
    clean["password_hash"] = password_hash

    # Auto-populate defaults
    if "created_at" not in clean or clean["created_at"] is None:
        clean["created_at"] = datetime.now(timezone.utc)

    clean.setdefault("role", "analyst")
    clean["_validated"] = True

    return clean


def validate_activity(doc: Document) -> Document:
    """
    Validate and normalize an activity log document.

    Required fields: type, message
    Auto-populated: timestamp, severity, _validated
    """
    clean = dict(doc)

    event_type = (clean.get("type") or "").strip()
    if not event_type:
        clean["type"] = "system"

    message = (clean.get("message") or "").strip()
    if not message:
        clean["message"] = "No message provided"

    # Auto-populate timestamp
    if "timestamp" not in clean or clean["timestamp"] is None:
        clean["timestamp"] = datetime.now(timezone.utc)

    clean.setdefault("severity", "info")
    clean["_validated"] = True

    return clean


def validate_cve_cache(doc: Document) -> Document:
    """Validate a CVE cache entry. Minimal validation — just ensure cve_id is present."""
    clean = dict(doc)
    cve_id = (clean.get("cve_id") or clean.get("id") or "").strip()
    if not cve_id:
        raise ValueError("CVE cache entry requires a 'cve_id' field.")

    clean.setdefault("cached_at", datetime.now(timezone.utc))
    clean["_validated"] = True
    return clean


# ─── Validator Registry ─────────────────────────────────────────────
# Maps collection name → validator function.
# Collections not listed here skip validation.
VALIDATORS: dict[str, Any] = {
    "threats": validate_threat,
    "network_scans": validate_scan,
    "users": validate_user,
    "activity_log": validate_activity,
    "cve_cache": validate_cve_cache,
}


def get_validator(collection_name: str):
    """Return the validator function for a collection, or None if none exists."""
    return VALIDATORS.get(collection_name)

"""
conftest.py — Pytest Configuration & Global Fixtures for NexShield
"""

import pytest
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture
def sample_scan_footprint():
    """Returns a sample mock scan footprint for target tests."""
    return {
        "scan_id": "test_scan_001",
        "host": "192.168.1.10",
        "scanned_at": "2026-07-22T12:00:00Z",
        "protocols": [
            {
                "protocol": "tcp",
                "ports": [
                    {
                        "port": 22,
                        "state": "open",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "7.5",
                        "cpe": "cpe:/a:openbsd:openssh:7.5",
                    },
                    {
                        "port": 80,
                        "state": "open",
                        "service": "http",
                        "product": "Apache httpd",
                        "version": "2.4.41",
                        "cpe": "cpe:/a:apache:http_server:2.4.41",
                    },
                    {
                        "port": 443,
                        "state": "filtered",
                        "service": "https",
                        "product": "",
                        "version": "",
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_threat():
    """Returns a sample threat item dict."""
    return {
        "name": "SSH Exposed",
        "severity": "medium",
        "host": "192.168.1.10",
        "cve_id": "CVE-2023-38408",
        "source": "PortRisk-Engine-v2",
        "detail": "SSH exposed on port 22",
        "tags": ["ssh", "sensitive_port"],
    }


@pytest.fixture
def client(monkeypatch):
    """Create a Flask test client for API route testing."""
    monkeypatch.delenv("MONGO_URI", raising=False)
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret-key-for-testing")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")

    from app import app, _provision_admin_user
    app.config["TESTING"] = True
    _provision_admin_user()

    with app.test_client() as test_client:
        yield test_client


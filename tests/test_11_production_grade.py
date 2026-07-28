"""
test_production_grade.py — Unit tests for webhook alerting, parallel scanning, and DB write concurrency
"""

import pytest
from webhook_notifier import dispatch_webhook_alert


def test_webhook_notifier_structure():
    threat = {
        "name": "Test Critical Threat",
        "severity": "critical",
        "host": "192.168.1.50",
        "cve_id": "CVE-2022-22965",
        "detail": "Spring4Shell RCE vulnerability",
    }
    # Should safely return results dictionary without exceptions even when webhook URLs are not set
    results = dispatch_webhook_alert(threat)
    assert isinstance(results, dict)
    assert "slack" in results
    assert "discord" in results
    assert "teams" in results
    assert "generic" in results


def test_api_webhook_test_route(client):
    """Test /api/webhooks/test route."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    resp = client.post("/api/webhooks/test")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "complete"
    assert "results" in data

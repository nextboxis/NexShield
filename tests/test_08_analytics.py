"""
test_analytics.py — Unit tests for high-performance analytical engine and trends endpoint
"""

import pytest
from config import get_analytics_summary


def test_get_analytics_summary():
    summary = get_analytics_summary()
    assert "total_threats" in summary
    assert "total_scans" in summary
    assert "total_hosts" in summary
    assert "severity_distribution" in summary
    assert "top_services" in summary
    assert isinstance(summary["severity_distribution"], dict)


def test_api_analytics_trends(client):
    """Test /api/analytics/trends endpoint."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    resp = client.get("/api/analytics/trends")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "complete"
    assert "analytics" in data
    assert "severity_distribution" in data["analytics"]

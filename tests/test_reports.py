"""
test_reports.py — Unit tests for multi-format report generator and compliance mapping
"""

import json
import pytest
from report_generator import (
    generate_report_content,
    compute_executive_summary,
    map_compliance,
)


def test_map_compliance():
    threat = {
        "name": "SMB Exposed",
        "detail": "SMBv1 active on port 445",
        "cve_id": "CVE-2017-0144",
        "severity": "critical",
    }
    compliance = map_compliance(threat)
    assert len(compliance) > 0
    frameworks = [c["framework"] for c in compliance]
    assert "PCI-DSS 4.0" in frameworks
    assert "ISO 27001:2022" in frameworks


def test_compute_executive_summary():
    threats = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "low"},
    ]
    scans = [{"host": "192.168.1.10"}]
    summary = compute_executive_summary(threats, scans)

    assert summary["total_threats"] == 3
    assert summary["total_scans"] == 1
    assert summary["risk_score"] > 0
    assert summary["risk_posture"] in ("CRITICAL RISK", "ELEVATED RISK", "MODERATE RISK", "SECURE / LOW RISK")


def test_generate_markdown_report():
    threats = [{"name": "Weak SSH", "severity": "medium", "host": "192.168.1.5", "cve_id": "CVE-2023-1234"}]
    scans = [{"host": "192.168.1.5"}]
    content = generate_report_content(threats, scans, fmt="markdown")

    assert "# 🛡️ NexShield Security & Penetration Testing Report" in content
    assert "Weak SSH" in content
    assert "192.168.1.5" in content


def test_generate_sarif_report():
    threats = [{"name": "Weak SSH", "severity": "high", "host": "192.168.1.5", "cve_id": "CVE-2023-1234"}]
    scans = []
    content = generate_report_content(threats, scans, fmt="sarif")

    doc = json.loads(content)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) > 0
    assert doc["runs"][0]["tool"]["driver"]["name"] == "NexShield Mission Control"


def test_generate_html_report():
    threats = [{"name": "HTTP Exposed", "severity": "low", "host": "192.168.1.10", "cve_id": "NONE"}]
    scans = []
    content = generate_report_content(threats, scans, fmt="html")

    assert "<!DOCTYPE html>" in content
    assert "NexShield Security Intelligence Report" in content


def test_api_report_generate_route(client):
    """Test /api/report/generate route."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    resp = client.get("/api/report/generate?format=markdown")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "complete"
    assert "content" in data
    assert data["format"] == "markdown"


def test_api_report_download_route(client):
    """Test /api/report/download route attachment."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    resp = client.get("/api/report/download?format=sarif")
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    assert "sarif" in resp.headers.get("Content-Disposition", "")

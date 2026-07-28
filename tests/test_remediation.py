"""
test_remediation.py — Unit tests for automated remediation script generator
"""

import pytest
from remediation_generator import generate_remediation_script, REMEDIATION_DB


def test_remediation_generator_ansible():
    threats = [
        {"name": "SMB Exposed", "detail": "SMBv1 on port 445", "tags": ["smb"], "source": "test"},
        {"name": "Telnet Exposure", "detail": "Unencrypted Telnet on port 23", "tags": ["telnet"], "source": "test"},
    ]
    script = generate_remediation_script(threats, target_host="192.168.1.10", fmt="ansible")
    assert "ansible.windows.win_optional_feature" in script or "ansible.builtin.service" in script
    assert "192.168.1.10" in script
    assert "---" in script


def test_remediation_generator_powershell():
    threats = [
        {"name": "SMB Exposed", "detail": "SMBv1 on port 445", "tags": ["smb"], "source": "test"},
    ]
    script = generate_remediation_script(threats, target_host="192.168.1.20", fmt="powershell")
    assert "Set-SmbServerConfiguration" in script
    assert "192.168.1.20" in script


def test_remediation_generator_bash():
    threats = [
        {"name": "Unencrypted HTTP", "detail": "HTTP without TLS on port 80", "tags": ["http"], "source": "test"},
    ]
    script = generate_remediation_script(threats, target_host="192.168.1.30", fmt="bash")
    assert "sudo ufw allow 443/tcp" in script
    assert "192.168.1.30" in script


def test_remediation_api_generate(client):
    """Test /api/remediation/generate route."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    resp = client.get("/api/remediation/generate?host=192.168.1.10&format=ansible")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "complete"
    assert "script" in data
    assert data["format"] == "ansible"


def test_remediation_api_download(client):
    """Test /api/remediation/download attachment endpoint."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    resp = client.get("/api/remediation/download?host=192.168.1.10&format=powershell")
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    assert "ps1" in resp.headers.get("Content-Disposition", "")

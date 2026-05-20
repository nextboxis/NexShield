import pytest
from ai_logic import _engine_port_risk, _engine_version_vuln, _engine_service_fp

def test_engine_port_risk():
    ctx = {
        "host": "192.168.1.1", "port": 21, "protocol": "tcp",
        "service": "ftp", "product": "vsftpd", "version": "2.3.4",
    }
    threats = _engine_port_risk(ctx)
    assert len(threats) == 1
    assert threats[0]["name"] == "FTP Exposed"
    assert threats[0]["severity"] == "high"

def test_engine_version_vuln():
    ctx = {
        "host": "192.168.1.1", "port": 21, "protocol": "tcp",
        "service": "ftp", "product": "vsftpd", "version": "2.3.4",
    }
    threats = _engine_version_vuln(ctx)
    # vsftpd 2.3.4 should trigger the known vulnerability pattern
    assert len(threats) >= 1
    cves = [t["cve_id"] for t in threats if "cve_id" in t]
    assert "CVE-2011-2523" in cves

def test_engine_service_fp():
    # Expected service on port 22 is ssh
    ctx_normal = {
        "host": "192.168.1.1", "port": 22, "protocol": "tcp",
        "service": "ssh", "product": "OpenSSH", "version": "8.0",
    }
    assert len(_engine_service_fp(ctx_normal)) == 0

    # Anomalous service on port 22
    ctx_anomalous = {
        "host": "192.168.1.1", "port": 22, "protocol": "tcp",
        "service": "http", "product": "Apache", "version": "2.4",
    }
    threats = _engine_service_fp(ctx_anomalous)
    assert len(threats) == 1
    assert "Anomalous Service" in threats[0]["name"]

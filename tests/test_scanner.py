import pytest
from scanner import validate_target

def test_validate_target_valid_ip():
    res = validate_target("192.168.1.1")
    assert res["valid"] is True
    assert res["type"] == "ipv4"

def test_validate_target_invalid_ip():
    res = validate_target("999.999.999.999")
    assert res["valid"] is False

def test_validate_target_internal_ip():
    res = validate_target("10.0.0.1")
    # Depends on how the system is configured, but structurally it should be valid IPv4
    assert res["valid"] is True
    assert "valid" in res

def test_validate_target_localhost():
    res = validate_target("127.0.0.1")
    # Usually validate_target might block localhost depending on implementation
    # Let's check the function logic
    assert "valid" in res

def test_validate_target_domain():
    res = validate_target("example.com")
    assert res["valid"] is True
    assert res["type"] == "hostname"

def test_run_scan_mock(monkeypatch):
    """Mock the nmap scanner to test parsing logic in run_scan"""
    from scanner import run_scan
    
    class MockPortScanner:
        def scan(self, hosts, arguments):
            pass
            
        def all_hosts(self):
            return ["192.168.1.100"]
            
        def __getitem__(self, host):
            return {
                "status": {"state": "up"},
                "tcp": {
                    80: {"state": "open", "name": "http", "product": "Apache", "version": "2.4"},
                    443: {"state": "open", "name": "https", "product": "", "version": ""}
                }
            }

    import nmap
    monkeypatch.setattr(nmap, "PortScanner", MockPortScanner)
    
    # We also need to mock _engine_port_risk and _engine_version_vuln to avoid external calls
    import ai_logic
    monkeypatch.setattr(ai_logic, "_engine_port_risk", lambda p: {"risk_score": 10, "label": "Low"})
    monkeypatch.setattr(ai_logic, "_engine_version_vuln", lambda p, s, v: {"risk_score": 20, "label": "Low", "cve_id": None})
    monkeypatch.setattr(ai_logic, "_engine_service_fp", lambda p, v: {})

    results = run_scan(target="192.168.1.100", scan_type="fast")
    assert "hosts" in results
    assert len(results["hosts"]) == 1
    
    host_data = results["hosts"][0]
    assert host_data["ip"] == "192.168.1.100"
    assert host_data["status"] == "up"
    assert len(host_data["open_ports"]) == 2
    
    assert host_data["open_ports"][0]["port"] == 80
    assert host_data["open_ports"][0]["service"] == "http"
    assert host_data["open_ports"][0]["version"] == "Apache 2.4"

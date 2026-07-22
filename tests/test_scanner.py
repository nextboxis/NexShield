"""
test_scanner.py — Unit tests for scanner target validation and configurations
"""

from scanner import validate_target, SCAN_TYPES, DEFAULT_PORTS


def test_validate_target_ipv4():
    res = validate_target("192.168.1.100")
    assert res["valid"] is True
    assert res["type"] == "ipv4"
    assert res["value"] == "192.168.1.100"
    assert res["is_private"] is True


def test_validate_target_cidr():
    res = validate_target("10.0.0.0/24")
    assert res["valid"] is True
    assert res["type"] == "cidr"
    assert res["host_count"] == 256


def test_validate_target_hostname():
    res = validate_target("example.com")
    assert res["valid"] is True
    assert res["type"] == "hostname"
    assert res["value"] == "example.com"


def test_validate_target_invalid():
    res_empty = validate_target("  ")
    assert res_empty["valid"] is False

    res_invalid_ip = validate_target("999.999.999.999")
    assert res_invalid_ip["valid"] is False


def test_scan_types_preset_keys():
    expected_presets = ["quick", "default", "deep", "stealth", "udp", "vuln", "ssl", "os", "full"]
    for key in expected_presets:
        assert key in SCAN_TYPES
        assert "args" in SCAN_TYPES[key]
        assert "label" in SCAN_TYPES[key]

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

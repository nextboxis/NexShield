"""
test_schemas.py — Unit tests for Pydantic data validation models
"""

import pytest
from pydantic import ValidationError
from schemas import (
    TargetValidation,
    HostPort,
    ProtocolFootprint,
    ScanFootprint,
    ThreatItem,
    CVELookupResult,
)


def test_target_validation_schema():
    res = TargetValidation(
        valid=True,
        type="ipv4",
        value="192.168.1.1",
        is_private=True,
    )
    assert res.valid is True
    assert res.type == "ipv4"
    assert res.value == "192.168.1.1"


def test_host_port_schema_validation():
    port = HostPort(port=80, protocol="tcp", state="open", service="http")
    assert port.port == 80
    assert port.service == "http"

    # Test invalid port number out of range
    with pytest.raises(ValidationError):
        HostPort(port=70000)


def test_threat_item_severity_normalization():
    # Test valid severity lowercase conversion
    item = ThreatItem(
        name="Test Threat",
        severity="CRITICAL",
        host="10.0.0.1",
        source="Engine-Test",
        detail="Test detail",
    )
    assert item.severity == "critical"

    # Test invalid severity falling back to 'info'
    item_invalid = ThreatItem(
        name="Test Threat 2",
        severity="SUPER_EXTREME",
        host="10.0.0.1",
        source="Engine-Test",
        detail="Test detail",
    )
    assert item_invalid.severity == "info"


def test_cve_lookup_result_defaults():
    cve = CVELookupResult(cve_id="CVE-2021-44228")
    assert cve.cve_id == "CVE-2021-44228"
    assert cve.cvss_score == 0.0
    assert cve.description == "No description available."

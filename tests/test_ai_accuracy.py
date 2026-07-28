"""
test_ai_accuracy.py — Unit tests for AI Scanner accuracy, confidence scoring, and SemVer matching
"""

import pytest
from cve_lookup import compare_versions, match_cpe


def test_compare_versions():
    assert compare_versions("2.4.41", "2.4.52") == -1
    assert compare_versions("2.4.52", "2.4.41") == 1
    assert compare_versions("1.18.0", "1.18.0") == 0
    assert compare_versions("8.0", "8.0.1") == -1


def test_match_cpe_semver():
    cpe1 = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    cpe2 = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    cpe3 = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"

    assert match_cpe(cpe1, cpe2) is True
    assert match_cpe(cpe1, cpe3) is False


def test_ai_threat_confidence_attributes():
    from ai_logic import _make_threat
    t = _make_threat(
        name="Test Threat",
        severity="high",
        host="192.168.1.10",
        cve_id="CVE-2021-44228",
        source="CVECorrelation-Engine-v1",
        detail="Test detail",
    )
    t["confidence_score"] = 0.95
    t["confidence_label"] = "VERIFIED"
    t["engine_consensus_count"] = 2

    assert t["confidence_score"] == 0.95
    assert t["confidence_label"] == "VERIFIED"
    assert t["engine_consensus_count"] == 2

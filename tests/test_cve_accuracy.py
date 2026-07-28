"""
test_cve_accuracy.py — Unit tests for >90% CVE Matching Accuracy Engine
"""

import pytest
from cve_lookup import check_cve_v5_version_match, match_cpe, PRODUCT_ALIASES


def test_cve_v5_version_match_valid_range():
    rules = [
        {
            "version": "2.4.0",
            "lessThan": "2.4.52",
            "status": "affected",
        }
    ]
    # Apache 2.4.41 is inside 2.4.0 <= v < 2.4.52 -> True
    assert check_cve_v5_version_match(rules, "2.4.41") is True

    # Apache 2.4.52 is NOT inside -> False
    assert check_cve_v5_version_match(rules, "2.4.52") is False

    # Apache 2.4.53 is NOT inside -> False
    assert check_cve_v5_version_match(rules, "2.4.53") is False


def test_cve_v5_version_match_lessthan_equal():
    rules = [
        {
            "version": "1.0.0",
            "lessThanOrEqual": "1.18.0",
            "status": "affected",
        }
    ]
    assert check_cve_v5_version_match(rules, "1.18.0") is True
    assert check_cve_v5_version_match(rules, "1.18.1") is False


def test_product_aliases_matching():
    # Nmap alias 'httpd' maps to 'http_server'
    cpe_scan = "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*"
    cpe_cve = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    assert match_cpe(cpe_scan, cpe_cve) is True

"""
test_cve.py — Unit tests for CPE normalization and CVE lookup functions
"""

from cve_lookup import normalize_cpe, match_cpe, get_local_cves_by_product


def test_normalize_cpe_v22_to_v23():
    cpe_v22 = "cpe:/a:apache:http_server:2.4.41"
    cpe_v23 = normalize_cpe(cpe_v22)
    assert cpe_v23.startswith("cpe:2.3:a:apache:http_server:2.4.41")


def test_normalize_cpe_already_v23():
    cpe_v23_input = "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*"
    assert normalize_cpe(cpe_v23_input) == cpe_v23_input


def test_match_cpe_exact():
    cpe1 = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    cpe2 = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    assert match_cpe(cpe1, cpe2) is True


def test_get_local_cves_empty_product():
    res = get_local_cves_by_product("")
    assert res == []

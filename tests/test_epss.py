"""
test_epss.py — Unit tests for EPSS integration and score lookups
"""

import pytest
from cve_lookup import get_epss_score, normalize_cpe, match_cpe


def test_get_epss_score_invalid_cve():
    res = get_epss_score("INVALID-ID")
    assert res["epss_score"] == 0.0
    assert "error" in res


def test_get_epss_score_cve_format():
    res = get_epss_score("CVE-2021-44228")
    assert "epss_score" in res
    assert "epss_percentile" in res
    assert isinstance(res["epss_score"], float)
    assert isinstance(res["epss_percentile"], float)
    assert 0.0 <= res["epss_score"] <= 1.0


def test_normalize_cpe_v22_to_v23():
    cpe_v22 = "cpe:/a:apache:http_server:2.4.41"
    cpe_v23 = normalize_cpe(cpe_v22)
    assert cpe_v23.startswith("cpe:2.3:a:apache:http_server:2.4.41")


def test_match_cpe_exact():
    cpe1 = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    cpe2 = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    assert match_cpe(cpe1, cpe2) is True

import pytest
from unittest.mock import patch, MagicMock
from cve_lookup import lookup_cve, _query_nvd

@patch("cve_lookup.requests.get")
def test_fetch_from_nvd_success(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "descriptions": [{"lang": "en", "value": "Log4j vuln"}]}}]}
    mock_get.return_value = mock_response

    result = _query_nvd({"cveId": "CVE-2021-44228"})
    assert result is not None
    assert "vulnerabilities" in result
    assert result["vulnerabilities"][0]["cve"]["id"] == "CVE-2021-44228"

@patch("cve_lookup.check_connection")
@patch("cve_lookup.cve_cache")
@patch("cve_lookup._query_nvd")
def test_lookup_cve_not_cached(mock_fetch, mock_cache, mock_check_conn):
    mock_check_conn.return_value = True
    mock_cache.find_one.return_value = None  # Not in cache
    
    mock_fetch.return_value = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10",
                "lastModified": "2021-12-10",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]}
            }
        }]
    }

    result = lookup_cve("CVE-2021-44228")
    assert result["cve_id"] == "CVE-2021-44228"
    assert result["score"] == 10.0
    mock_cache.update_one.assert_called_once()

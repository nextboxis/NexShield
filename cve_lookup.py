"""
cve_lookup.py — CVE Lookup from NVD (National Vulnerability Database)
Queries the NVD 2.0 API for CVE details and caches results in MongoDB.
Supports multiple query types: CVE ID, CPE Name, CVE Tags, CVSS v2 metrics/severity.
"""

import requests  # type: ignore
from datetime import datetime, timezone, timedelta
from config import cve_cache, check_connection  # type: ignore

# ═════════════════════════════════════════════════════════════════════
#  NVD API Configuration
# ═════════════════════════════════════════════════════════════════════

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "1e2b3133-a633-46f8-9c6f-d98791213a66"
NVD_HEADERS = {"apiKey": NVD_API_KEY}
CACHE_DAYS = 7  # Re-fetch after 7 days


# ═════════════════════════════════════════════════════════════════════
#  Internal Helpers
# ═════════════════════════════════════════════════════════════════════

def _cached_payload(cached: dict, stale: bool = False) -> dict:
    payload = {
        "cve_id": cached["cve_id"],
        "description": cached.get("description", ""),
        "severity": cached.get("severity", "unknown"),
        "score": cached.get("score", 0),
        "published": cached.get("published", ""),
        "modified": cached.get("modified", ""),
        "references": cached.get("references", []),
        "cached": True,
    }
    if stale:
        payload["stale"] = True
    return payload


def _parse_cve_item(cve_data: dict) -> dict:
    """Parse a single CVE item from the NVD response into a normalized dict."""
    # Parse description
    descriptions = cve_data.get("descriptions", [])
    desc_en = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    # Parse CVSS score (prefer v3.1 > v3.0 > v2)
    metrics = cve_data.get("metrics", {})
    score = 0
    severity = "unknown"
    cvss_vector = ""
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:  # type: ignore
            cvss = metrics[version][0].get("cvssData", {})  # type: ignore
            score = cvss.get("baseScore", 0)
            severity = cvss.get("baseSeverity", "UNKNOWN").lower()
            cvss_vector = cvss.get("vectorString", "")
            break

    # Parse references
    refs = cve_data.get("references", [])
    ref_urls = [r.get("url", "") for r in refs[:5]]

    # Parse dates
    published = cve_data.get("published", "")
    modified = cve_data.get("lastModified", "")

    # Parse tags (e.g., "disputed")
    tags = cve_data.get("vulnStatus", "")

    return {
        "cve_id": cve_data.get("id", ""),
        "description": desc_en,
        "severity": severity,
        "score": score,
        "cvss_vector": cvss_vector,
        "published": published,
        "modified": modified,
        "references": ref_urls,
        "status": tags,
    }


def _query_nvd(params: dict, timeout: int = 30) -> dict:
    """
    Send a query to the NVD 2.0 API with API key authentication.
    Returns the raw JSON response or an error dict.
    """
    try:
        resp = requests.get(NVD_API, params=params, headers=NVD_HEADERS, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        return {"error": "NVD API request timed out. Try again later."}
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        if status == 403:
            return {"error": "NVD API key is invalid or rate-limited (403 Forbidden)."}
        elif status == 404:
            return {"error": "NVD resource not found (404)."}
        return {"error": f"NVD API HTTP error {status}: {str(e)}"}
    except Exception as e:
        return {"error": f"NVD API request failed: {str(e)}"}


# ═════════════════════════════════════════════════════════════════════
#  Primary Lookup — by CVE ID
# ═════════════════════════════════════════════════════════════════════

def lookup_cve(cve_id: str) -> dict:
    """
    Look up a CVE by ID. Returns cached result if available,
    otherwise queries the NVD API and caches the response.
    Example: lookup_cve("CVE-2019-1010218")
    """
    cve_id = cve_id.strip().upper()

    # ── Check cache first ────────────────────────────────────────
    cached = None
    if check_connection():
        cached = cve_cache.find_one({"cve_id": cve_id})
        if cached:
            fetched_at = cached.get("fetched_at")
            if isinstance(fetched_at, datetime):
                if fetched_at.tzinfo is None:
                    fetched_at = fetched_at.replace(tzinfo=timezone.utc)
                if fetched_at >= datetime.now(timezone.utc) - timedelta(days=CACHE_DAYS):
                    return _cached_payload(cached)
            else:
                return _cached_payload(cached)

    # ── Query NVD API ────────────────────────────────────────────
    data = _query_nvd({"cveId": cve_id})
    if "error" in data:
        if cached:
            fallback = _cached_payload(cached, stale=True)
            fallback["warning"] = data["error"]
            return fallback
        return {"cve_id": cve_id, "error": data["error"]}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"cve_id": cve_id, "error": "CVE not found in NVD database."}

    result = _parse_cve_item(vulns[0].get("cve", {}))
    result["cached"] = False

    # ── Cache the result ─────────────────────────────────────────
    if check_connection():
        cve_cache.update_one(
            {"cve_id": cve_id},
            {"$set": {**result, "fetched_at": datetime.now(timezone.utc)}},
            upsert=True,
        )

    return result


# ═════════════════════════════════════════════════════════════════════
#  Lookup by CPE Name
# ═════════════════════════════════════════════════════════════════════

def lookup_by_cpe(cpe_name: str, results_per_page: int = 20) -> dict:
    """
    Find CVEs affecting a specific CPE product.
    Example: lookup_by_cpe("cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*")
    """
    data = _query_nvd({"cpeName": cpe_name, "resultsPerPage": results_per_page})
    if "error" in data:
        return data

    vulns = data.get("vulnerabilities", [])
    return {
        "query_type": "cpeName",
        "query_value": cpe_name,
        "total_results": data.get("totalResults", 0),
        "results_returned": len(vulns),
        "vulnerabilities": [_parse_cve_item(v.get("cve", {})) for v in vulns],
    }


# ═════════════════════════════════════════════════════════════════════
#  Lookup by CVE Tag (e.g. "disputed")
# ═════════════════════════════════════════════════════════════════════

def lookup_by_tag(tag: str, results_per_page: int = 20) -> dict:
    """
    Find CVEs with a specific tag.
    Example: lookup_by_tag("disputed")
    """
    data = _query_nvd({"cveTag": tag, "resultsPerPage": results_per_page})
    if "error" in data:
        return data

    vulns = data.get("vulnerabilities", [])
    return {
        "query_type": "cveTag",
        "query_value": tag,
        "total_results": data.get("totalResults", 0),
        "results_returned": len(vulns),
        "vulnerabilities": [_parse_cve_item(v.get("cve", {})) for v in vulns],
    }


# ═════════════════════════════════════════════════════════════════════
#  Lookup by CVSS v2 Metrics Vector
# ═════════════════════════════════════════════════════════════════════

def lookup_by_cvss_v2_metrics(vector: str, results_per_page: int = 20) -> dict:
    """
    Find CVEs matching a specific CVSS v2 vector string.
    Example: lookup_by_cvss_v2_metrics("AV:N/AC:H/Au:N/C:C/I:C/A:C")
    Example: lookup_by_cvss_v2_metrics("AV:L/AC:H/Au:M/C:N/I:N/A:N")
    """
    data = _query_nvd({"cvssV2Metrics": vector, "resultsPerPage": results_per_page})
    if "error" in data:
        return data

    vulns = data.get("vulnerabilities", [])
    return {
        "query_type": "cvssV2Metrics",
        "query_value": vector,
        "total_results": data.get("totalResults", 0),
        "results_returned": len(vulns),
        "vulnerabilities": [_parse_cve_item(v.get("cve", {})) for v in vulns],
    }


# ═════════════════════════════════════════════════════════════════════
#  Lookup by CVSS v2 Severity
# ═════════════════════════════════════════════════════════════════════

def lookup_by_cvss_v2_severity(severity: str, results_per_page: int = 20) -> dict:
    """
    Find CVEs by CVSS v2 severity level.
    Example: lookup_by_cvss_v2_severity("LOW")
    Allowed values: LOW, MEDIUM, HIGH
    """
    severity = severity.strip().upper()
    if severity not in ("LOW", "MEDIUM", "HIGH"):
        return {"error": "CVSS v2 severity must be LOW, MEDIUM, or HIGH."}

    data = _query_nvd({"cvssV2Severity": severity, "resultsPerPage": results_per_page})
    if "error" in data:
        return data

    vulns = data.get("vulnerabilities", [])
    return {
        "query_type": "cvssV2Severity",
        "query_value": severity,
        "total_results": data.get("totalResults", 0),
        "results_returned": len(vulns),
        "vulnerabilities": [_parse_cve_item(v.get("cve", {})) for v in vulns],
    }


# ═════════════════════════════════════════════════════════════════════
#  Universal Search (auto-detects query type)
# ═════════════════════════════════════════════════════════════════════

def search_nvd(query: str, query_type: str = "auto", results_per_page: int = 20) -> dict:
    """
    Universal NVD search — auto-detects query type or accepts explicit type.
    Supported types: cveId, cpeName, cveTag, cvssV2Metrics, cvssV2Severity
    """
    query = query.strip()

    if query_type == "auto":
        if query.upper().startswith("CVE-"):
            return lookup_cve(query)
        elif query.lower().startswith("cpe:"):
            return lookup_by_cpe(query, results_per_page)
        elif query.upper() in ("LOW", "MEDIUM", "HIGH"):
            return lookup_by_cvss_v2_severity(query, results_per_page)
        elif "/" in query and query.startswith("AV:"):
            return lookup_by_cvss_v2_metrics(query, results_per_page)
        else:
            return lookup_by_tag(query, results_per_page)

    dispatch = {
        "cveId": lambda: lookup_cve(query),
        "cpeName": lambda: lookup_by_cpe(query, results_per_page),
        "cveTag": lambda: lookup_by_tag(query, results_per_page),
        "cvssV2Metrics": lambda: lookup_by_cvss_v2_metrics(query, results_per_page),
        "cvssV2Severity": lambda: lookup_by_cvss_v2_severity(query, results_per_page),
    }

    handler = dispatch.get(query_type)
    if handler:
        return handler()
    return {"error": f"Unknown query type: {query_type}"}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_lookup.py <query> [query_type]")
        print("  query_type: auto (default), cveId, cpeName, cveTag, cvssV2Metrics, cvssV2Severity")
        print("\nExamples:")
        print("  python cve_lookup.py CVE-2019-1010218")
        print('  python cve_lookup.py "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"')
        print("  python cve_lookup.py disputed cveTag")
        print('  python cve_lookup.py "AV:N/AC:H/Au:N/C:C/I:C/A:C" cvssV2Metrics')
        print("  python cve_lookup.py LOW cvssV2Severity")
        sys.exit(0)

    query = sys.argv[1]
    qtype = sys.argv[2] if len(sys.argv) > 2 else "auto"

    print(f"[*] Querying NVD — type={qtype}, query={query}")
    result = search_nvd(query, qtype)

    if "error" in result:
        print(f"  [!] Error: {result['error']}")
    elif "vulnerabilities" in result:
        print(f"  Total results: {result['total_results']}")
        print(f"  Returned: {result['results_returned']}")
        for vuln in result["vulnerabilities"]:
            print(f"    {vuln['cve_id']} | {vuln['severity'].upper():8s} | score={vuln['score']} | {vuln['description'][:80]}...")
    else:
        for k, v in result.items():
            print(f"  {k}: {v}")

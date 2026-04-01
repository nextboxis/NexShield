"""
cve_lookup.py — CVE Lookup from NVD (National Vulnerability Database)
Queries the NVD 2.0 API for CVE details and caches results in MongoDB.
"""

import requests  # type: ignore
from datetime import datetime, timezone, timedelta
from config import cve_cache, check_connection  # type: ignore

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DAYS = 7  # Re-fetch after 7 days


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


def lookup_cve(cve_id: str) -> dict:
    """
    Look up a CVE by ID. Returns cached result if available,
    otherwise queries the NVD API and caches the response.
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
    try:
        resp = requests.get(NVD_API, params={"cveId": cve_id}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        if cached:
            fallback = _cached_payload(cached, stale=True)
            fallback["warning"] = f"NVD refresh failed: {str(e)}"
            return fallback
        return {"cve_id": cve_id, "error": f"NVD API request failed: {str(e)}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"cve_id": cve_id, "error": "CVE not found in NVD database."}

    cve_data = vulns[0].get("cve", {})

    # Parse description
    descriptions = cve_data.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")

    # Parse CVSS score
    metrics = cve_data.get("metrics", {})
    score = 0
    severity = "unknown"
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:  # type: ignore
            cvss = metrics[version][0].get("cvssData", {})  # type: ignore
            score = cvss.get("baseScore", 0)
            severity = cvss.get("baseSeverity", "UNKNOWN").lower()
            break

    # Parse references
    refs = cve_data.get("references", [])
    ref_urls = [r.get("url", "") for r in refs[:5]]

    # Parse dates
    published = cve_data.get("published", "")
    modified = cve_data.get("lastModified", "")

    result = {
        "cve_id": cve_id,
        "description": desc_en,
        "severity": severity,
        "score": score,
        "published": published,
        "modified": modified,
        "references": ref_urls,
        "cached": False,
    }

    # ── Cache the result ─────────────────────────────────────────
    if check_connection():
        cve_cache.update_one(
            {"cve_id": cve_id},
            {"$set": {**result, "fetched_at": datetime.now(timezone.utc)}},
            upsert=True,
        )

    return result


if __name__ == "__main__":
    import sys
    cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"[*] Looking up {cve}...")
    info = lookup_cve(cve)
    for k, v in info.items():
        print(f"  {k}: {v}")

"""
cve_lookup.py — CVE Lookup from NVD (National Vulnerability Database)
Queries the NVD 2.0 API for CVE details and caches results in MongoDB.
Supports multiple query types: CVE ID, CPE Name, CVE Tags, CVSS v2 metrics/severity.
"""

import os
import json
import re
import requests  # type: ignore
from pathlib import Path
from datetime import datetime, timezone, timedelta
from config import cve_cache, check_connection  # type: ignore

# ═════════════════════════════════════════════════════════════════════
#  NVD API Configuration
# ═════════════════════════════════════════════════════════════════════

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
CACHE_DAYS = 7  # Re-fetch after 7 days

import logging
import threading

logger = logging.getLogger(__name__)

# Local CVE repository path — relative to this file's directory
_REPO_ROOT = Path(__file__).parent
_PRIMARY_CVE_DIR = _REPO_ROOT / "cve_data" / "cvelistV5-main" / "cves"
_ALT_CVE_DIR = _REPO_ROOT / "cve_data" / "cves"
_FALLBACK_CVE_DIR = _REPO_ROOT / "cvelistV5-main" / "cvelistV5-main" / "cves"

CVELIST_DIR = (
    _PRIMARY_CVE_DIR if _PRIMARY_CVE_DIR.exists()
    else (_ALT_CVE_DIR if _ALT_CVE_DIR.exists()
    else _FALLBACK_CVE_DIR)
)

_cvelist_index = {}
_cvelist_index_lock = threading.Lock()
_cvelist_index_loaded = False
_cvelist_index_thread = None

def _build_cvelist_index():
    global _cvelist_index_loaded, _cvelist_index
    cves_dir = CVELIST_DIR
    if not cves_dir.exists():
        logger.debug(f"Local CVELIST_DIR does not exist at {cves_dir}")
        return
    
    local_index = {}
    try:
        for year_dir in cves_dir.iterdir():
            if not year_dir.is_dir() or not year_dir.name.isdigit():
                continue
            for chunk_dir in year_dir.iterdir():
                if not chunk_dir.is_dir():
                    continue
                for json_file in chunk_dir.glob("*.json"):
                    cve_id = json_file.stem
                    try:
                        with open(json_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        containers = data.get("containers", {})
                        cna = containers.get("cna", {})
                        affected = cna.get("affected", [])
                        for aff in affected:
                            product = aff.get("product", "").strip().lower()
                            if product and product not in ("n/a", "unknown"):
                                if product not in local_index:
                                    local_index[product] = []
                                local_index[product].append(cve_id)
                    except (json.JSONDecodeError, OSError) as exc:
                        logger.debug(f"Failed to read/parse local CVE file {json_file}: {exc}")
        with _cvelist_index_lock:
            _cvelist_index = local_index
            _cvelist_index_loaded = True
            logger.info(f"Loaded {len(_cvelist_index)} product entries into local CVE index.")
    except Exception as exc:
        logger.warning(f"Error during local CVE index build: {exc}")


def start_indexing():
    global _cvelist_index_thread
    with _cvelist_index_lock:
        if _cvelist_index_thread is None:
            _cvelist_index_thread = threading.Thread(target=_build_cvelist_index, daemon=True)
            _cvelist_index_thread.start()

# Start indexing immediately when cve_lookup is imported
start_indexing()

def get_local_cves_by_product(product_name: str) -> list:
    """Return a list of parsed CVE documents from the local repository matching the product name."""
    start_indexing() # Ensure it's running
    
    product_key = product_name.strip().lower()
    if not product_key:
        return []
        
    with _cvelist_index_lock:
        cve_ids = list(_cvelist_index.get(product_key, []))
        
    results = []
    for cve_id in cve_ids:
        # Reuse existing lookup_cve which checks/updates DB cache
        cve_data = lookup_cve(cve_id)
        if cve_data and "error" not in cve_data:
            results.append(cve_data)
    return results


# ═════════════════════════════════════════════════════════════════════
#  Internal Helpers
# ═════════════════════════════════════════════════════════════════════

def normalize_cpe(cpe_str: str) -> str:
    """Normalize a CPE string from nmap format (v2.2) to NVD CPE v2.3 format."""
    cpe_str = cpe_str.strip()
    if not cpe_str:
        return ""
    
    # If it's already v2.3, return it
    if cpe_str.startswith("cpe:2.3:"):
        return cpe_str
        
    # If it's v2.2 format: cpe:/a:vendor:product:version:...
    if cpe_str.startswith("cpe:/"):
        parts = cpe_str.split(":")
        # parts[0] is "cpe"
        # parts[1] is "/a", "/o", "/h" etc.
        part = parts[1].replace("/", "") if len(parts) > 1 else "a"
        vendor = parts[2] if len(parts) > 2 else "*"
        product = parts[3] if len(parts) > 3 else "*"
        version = parts[4] if len(parts) > 4 else "*"
        update = parts[5] if len(parts) > 5 else "*"
        
        # build CPE 2.3 string
        cpe_23_parts = ["cpe", "2.3", part, vendor, product, version, update, "*", "*", "*", "*", "*", "*"]
        # Fill/adjust with remaining parts from input if any
        for i in range(6, len(parts)):
            if i - 6 + 7 < len(cpe_23_parts):
                cpe_23_parts[i - 6 + 7] = parts[i]
                
        return ":".join(cpe_23_parts)
        
    return cpe_str


PRODUCT_ALIASES = {
    "httpd": "http_server",
    "apache": "http_server",
    "nginx": "nginx",
    "openssh": "openssh",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "mariadb": "mariadb",
    "mysql": "mysql",
    "samba": "samba",
    "tomcat": "tomcat",
}


def check_cve_v5_version_match(version_rules: list[dict], installed_version: str) -> bool:
    """
    Evaluates CVE 5.0 version rules against an installed service version.
    Returns True ONLY if the installed version falls within confirmed affected boundaries.
    Does not assume unknown/empty versions are affected (prevents false positives).
    """
    if not installed_version or not version_rules:
        return False

    installed_version = str(installed_version).strip()
    if not installed_version or installed_version == "*":
        return False

    for rule in version_rules:
        status = rule.get("status", "affected").lower()
        if status != "affected":
            continue

        version_start = str(rule.get("version", "0")).strip()
        less_than = str(rule.get("lessThan") or "").strip()
        less_than_equal = str(rule.get("lessThanOrEqual") or "").strip()

        # Wildcard / universal affected rules
        if version_start in ("*", "all") or less_than in ("*", "all") or less_than_equal in ("*", "all"):
            return True

        if compare_versions(installed_version, version_start) >= 0:
            if less_than and compare_versions(installed_version, less_than) < 0:
                return True
            if less_than_equal and compare_versions(installed_version, less_than_equal) <= 0:
                return True
            if not less_than and not less_than_equal and compare_versions(installed_version, version_start) == 0:
                return True

    return False


def compare_versions(v1: str, v2: str) -> int:
    """
    Compares two version strings semantically.
    Returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
    """
    def _clean_version(v):
        return [int(x) for x in re.findall(r"\d+", str(v or ""))]

    parts1 = _clean_version(v1)
    parts2 = _clean_version(v2)

    max_len = max(len(parts1), len(parts2))
    parts1 += [0] * (max_len - len(parts1))
    parts2 += [0] * (max_len - len(parts2))

    if parts1 < parts2:
        return -1
    elif parts1 > parts2:
        return 1
    return 0


def match_cpe(cpe_candidate: str, cpe_criteria: str, allow_wildcard_candidate: bool = False) -> bool:
    """
    Check if a candidate CPE (e.g., from scan) matches a criteria CPE (e.g., from CVE).
    Both should be in CPE v2.3 format with Semantic Versioning check.
    Prevents false positives when candidate version is unknown or wildcard.
    """
    if not cpe_candidate or not cpe_criteria:
        return False
        
    cpe_candidate = normalize_cpe(cpe_candidate)
    cpe_criteria = normalize_cpe(cpe_criteria)
        
    cand_parts = cpe_candidate.split(":")
    crit_parts = cpe_criteria.split(":")
    
    if len(cand_parts) < 5 or len(crit_parts) < 5:
        return False
        
    # We match the first 5 critical parts: part, vendor, product
    for idx in [2, 3, 4]:
        c_part = cand_parts[idx].lower() if idx < len(cand_parts) else "*"
        cr_part = crit_parts[idx].lower() if idx < len(crit_parts) else "*"
        if c_part == "*" or cr_part == "*":
            continue
        # Apply Product Aliases mapping
        c_alias = PRODUCT_ALIASES.get(c_part, c_part)
        cr_alias = PRODUCT_ALIASES.get(cr_part, cr_part)
        if c_alias != cr_alias:
            return False
            
    # For version (idx 5):
    c_ver = cand_parts[5].lower() if 5 < len(cand_parts) else "*"
    cr_ver = crit_parts[5].lower() if 5 < len(crit_parts) else "*"

    # Candidate with unknown/wildcard version should NOT match specific CVE criteria
    # unless allow_wildcard_candidate is explicitly True
    if c_ver in ("*", "-", "") and not allow_wildcard_candidate:
        return False

    # If criteria specifies a version and candidate specifies a version, check match
    if cr_ver not in ("*", "-", "") and c_ver not in ("*", "-", ""):
        if compare_versions(c_ver, cr_ver) != 0:
            return False
            
    return True



_epss_mem_cache = {}
_epss_cache_lock = threading.Lock()


def get_epss_score(cve_id: str, timeout: int = 5) -> dict:
    """
    Fetch EPSS (Exploit Prediction Scoring System) score from FIRST.org API.
    Returns dict with keys: epss_score (float 0.0-1.0), epss_percentile (float 0.0-1.0), and date.
    """
    canonical_cve = _canonicalize_cve_id(cve_id)
    if not canonical_cve:
        return {"epss_score": 0.0, "epss_percentile": 0.0, "error": "Invalid CVE format"}

    with _epss_cache_lock:
        if canonical_cve in _epss_mem_cache:
            return _epss_mem_cache[canonical_cve]

    try:
        url = f"https://api.first.org/data/v1/epss?cve={canonical_cve}"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            res_json = resp.json()
            data_list = res_json.get("data", [])
            if data_list:
                item = data_list[0]
                score = float(item.get("epss", 0.0))
                percentile = float(item.get("percentile", 0.0))
                result = {
                    "epss_score": round(score, 4),
                    "epss_percentile": round(percentile, 4),
                    "epss_date": item.get("date", ""),
                }
                with _epss_cache_lock:
                    _epss_mem_cache[canonical_cve] = result
                return result
    except Exception as exc:
        logger.debug(f"EPSS API fetch failed for {canonical_cve}: {exc}")

    fallback = {"epss_score": 0.0, "epss_percentile": 0.0}
    with _epss_cache_lock:
        _epss_mem_cache[canonical_cve] = fallback
    return fallback


def _cached_payload(cached: dict, stale: bool = False) -> dict:
    payload = {
        "cve_id": cached["cve_id"],
        "description": cached.get("description", ""),
        "severity": cached.get("severity", "unknown"),
        "score": cached.get("score", 0),
        "epss_score": cached.get("epss_score", 0.0),
        "epss_percentile": cached.get("epss_percentile", 0.0),
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

    # Parse CPE criteria
    cpes = []
    configurations = cve_data.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                criteria = match.get("criteria", "")
                if criteria and criteria not in cpes:
                    cpes.append(criteria)

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
        "cpes": cpes,
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
# ═════════════════════════════════════════════════════════════════════
#  Primary Lookup — by CVE ID
# ═════════════════════════════════════════════════════════════════════

from typing import Optional

_LOCAL_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_LOCAL_YEAR_DIR_RE = re.compile(r"^\d{4}$")
_LOCAL_BLOCK_DIR_RE = re.compile(r"^\d+xxx$")
_LOCAL_FILE_STEM_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

def _canonicalize_cve_id(cve_id: str) -> Optional[str]:
    """Return canonical CVE ID or None if invalid."""
    candidate = (cve_id or "").strip().upper()
    if not _LOCAL_CVE_RE.fullmatch(candidate):
        return None
    return candidate

def _build_local_cve_path(year: str, seq: str) -> Optional[Path]:
    """Build a safe local path for a CVE JSON file inside CVELIST_DIR."""
    year = (year or "").strip()
    seq = (seq or "").strip()

    if len(year) != 4 or not year.isdigit():
        return None
    if not seq.isdigit():
        return None

    canonical_cve_id = f"CVE-{year}-{seq}"
    block = (seq[:-3] + "xxx") if len(seq) > 3 else "0xxx"

    if not _LOCAL_YEAR_DIR_RE.fullmatch(year):
        return None
    if not _LOCAL_BLOCK_DIR_RE.fullmatch(block):
        return None
    if not _LOCAL_FILE_STEM_RE.fullmatch(canonical_cve_id):
        return None

    base_dir = CVELIST_DIR.resolve()
    cve_path = base_dir.joinpath(year, block, f"{canonical_cve_id}.json").resolve()
    try:
        cve_path.relative_to(base_dir)
    except ValueError:
        return None
    return cve_path


def _parse_cvelist_v5(cve_id: str) -> Optional[dict]:
    """Reads and parses a CVE from the local cvelistV5-main directory."""
    try:
        cve_id = (cve_id or "").strip().upper()
        if not _LOCAL_CVE_RE.fullmatch(cve_id):
            return None

        parts = cve_id.split("-")
        if len(parts) != 3:
            return None
        year = parts[1]
        seq = parts[2]

        cve_path = _build_local_cve_path(year, seq)
        if cve_path is None or not cve_path.exists():
            return None

        with open(cve_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        cve_metadata = data.get("cveMetadata", {})
        status = cve_metadata.get("state", "UNKNOWN")
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        
        desc_en = "No description available."
        for d in cna.get("descriptions", []):
            if d.get("lang") == "en":
                desc_en = d.get("value", desc_en)
                break
                
        metrics = cna.get("metrics", [])
        if not metrics and "adp" in containers:
            for adp in containers["adp"]:
                if "metrics" in adp:
                    metrics = adp["metrics"]
                    break

        score = 0
        severity = "unknown"
        cvss_vector = ""
        for m in metrics:
            for k in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if k in m:
                    score = m[k].get("baseScore", 0)
                    severity = m[k].get("baseSeverity", "UNKNOWN").lower()
                    cvss_vector = m[k].get("vectorString", "")
                    break
            if score: break
                
        published = cve_metadata.get("datePublished", "")
        modified = cve_metadata.get("dateUpdated", "")
        refs = [r.get("url", "") for r in cna.get("references", [])[:5] if "url" in r]
        
        cpes = []
        version_rules = []
        for aff in cna.get("affected", []):
            vendor = aff.get("vendor", "*").replace(" ", "_").lower()
            product = aff.get("product", "*").replace(" ", "_").lower()
            if vendor in ("n/a", "unknown"): vendor = "*"
            if product in ("n/a", "unknown"): product = "*"
            synthetic_cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*"
            if synthetic_cpe not in cpes:
                cpes.append(synthetic_cpe)
            for v_entry in aff.get("versions", []):
                version_rules.append(v_entry)
                
        return {
            "cve_id": cve_id,
            "description": desc_en,
            "severity": severity,
            "score": score,
            "cvss_vector": cvss_vector,
            "published": published,
            "modified": modified,
            "references": refs,
            "status": status,
            "cpes": cpes,
            "version_rules": version_rules,
            "cached": True
        }
    except Exception:
        return None

def lookup_cve(cve_id: str) -> dict:
    """
    Look up a CVE by ID. Returns cached result if available,
    otherwise queries the NVD API and caches the response.
    Example: lookup_cve("CVE-2019-1010218")
    """
    canonical_cve_id = _canonicalize_cve_id(cve_id)
    if canonical_cve_id is None:
        return {"cve_id": (cve_id or "").strip().upper(), "error": "Invalid CVE identifier. Use the format CVE-YYYY-NNNN."}
    cve_id = canonical_cve_id

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

    # ── Check local cvelistV5-main ───────────────────────────────
    local_data = _parse_cvelist_v5(cve_id)
    if local_data:
        epss_info = get_epss_score(cve_id)
        local_data["epss_score"] = epss_info.get("epss_score", 0.0)
        local_data["epss_percentile"] = epss_info.get("epss_percentile", 0.0)
        if check_connection():
            cve_cache.update_one(
                {"cve_id": cve_id},
                {"$set": {**local_data, "fetched_at": datetime.now(timezone.utc)}},
                upsert=True,
            )
        return local_data

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
    epss_info = get_epss_score(cve_id)
    result["epss_score"] = epss_info.get("epss_score", 0.0)
    result["epss_percentile"] = epss_info.get("epss_percentile", 0.0)
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
    cpe_name = normalize_cpe(cpe_name)
    data = _query_nvd({"cpeName": cpe_name, "resultsPerPage": results_per_page})
    if "error" in data:
        return data

    vulns = data.get("vulnerabilities", [])
    parsed_vulns = [_parse_cve_item(v.get("cve", {})) for v in vulns]

    # Cache the results in MongoDB/TinyDB
    if check_connection() and parsed_vulns:
        for vuln in parsed_vulns:
            cve_cache.update_one(
                {"cve_id": vuln["cve_id"]},
                {"$set": {**vuln, "fetched_at": datetime.now(timezone.utc)}},
                upsert=True,
            )

    return {
        "query_type": "cpeName",
        "query_value": cpe_name,
        "total_results": data.get("totalResults", 0),
        "results_returned": len(vulns),
        "vulnerabilities": parsed_vulns,
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


# ═════════════════════════════════════════════════════════════════════
#  Per-Host CVE Intelligence
# ═════════════════════════════════════════════════════════════════════

def get_cves_for_host(ip: str) -> list:
    """
    Return all CVEs correlated to a specific host IP.
    Looks up threats for that host that have a CVE ID, then fetches
    enriched CVE data from local cache / cvelistV5 directory.
    """
    from config import threats  # type: ignore  # avoid circular import
    host_threats = list(threats.find({"host": ip}))
    cve_map = {}
    for t in host_threats:
        cve_id = (t.get("cve_id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        if cve_id in cve_map:
            continue
        # Try local cache first
        cached = cve_cache.find_one({"cve_id": cve_id})
        if cached:
            cve_map[cve_id] = {
                "cve_id": cve_id,
                "description": cached.get("description", ""),
                "severity": cached.get("severity", "unknown"),
                "score": cached.get("score", 0),
                "cvss_vector": cached.get("cvss_vector", ""),
                "published": cached.get("published", ""),
                "references": cached.get("references", []),
                "cpes": cached.get("cpes", []),
                "threat_name": t.get("name", ""),
                "source": t.get("source", ""),
            }
        else:
            # Fallback: parse directly from cvelistV5 folder
            local = _parse_cvelist_v5(cve_id)
            if local:
                local["threat_name"] = t.get("name", "")
                local["source"] = t.get("source", "")
                cve_map[cve_id] = local
                # Cache it for next time
                if check_connection():
                    from datetime import datetime, timezone
                    cve_cache.update_one(
                        {"cve_id": cve_id},
                        {"$set": {**local, "fetched_at": datetime.now(timezone.utc)}},
                        upsert=True,
                    )

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    return sorted(cve_map.values(), key=lambda x: sev_order.get(x.get("severity", "unknown"), 4))


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

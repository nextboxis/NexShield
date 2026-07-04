import os
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Add parent directory to path to import config
sys.path.append(str(Path(__file__).parent.parent))

from config import cve_cache, check_connection

def parse_v5_cve(data):
    """Parse CVE v5.1 JSON to NexShield schema."""
    cve_metadata = data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId", "")
    
    if not cve_id:
        return None
        
    status = cve_metadata.get("state", "UNKNOWN")
    
    # Try to extract from CNA (CNA contains the official data)
    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    
    # Description
    descriptions = cna.get("descriptions", [])
    desc_en = "No description available."
    for d in descriptions:
        if d.get("lang") == "en":
            desc_en = d.get("value", desc_en)
            break
            
    # Metrics (CVSS)
    metrics = cna.get("metrics", [])
    if not metrics and "adp" in containers:
        for adp in containers["adp"]:
            if "metrics" in adp:
                metrics = adp["metrics"]
                break

    score = 0
    severity = "unknown"
    cvss_vector = ""
    
    for metric in metrics:
        if "cvssV3_1" in metric:
            cvss = metric["cvssV3_1"]
            score = cvss.get("baseScore", 0)
            severity = cvss.get("baseSeverity", "UNKNOWN").lower()
            cvss_vector = cvss.get("vectorString", "")
            break
        elif "cvssV3_0" in metric:
            cvss = metric["cvssV3_0"]
            score = cvss.get("baseScore", 0)
            severity = cvss.get("baseSeverity", "UNKNOWN").lower()
            cvss_vector = cvss.get("vectorString", "")
            break
        elif "cvssV2_0" in metric:
            cvss = metric["cvssV2_0"]
            score = cvss.get("baseScore", 0)
            severity = cvss.get("baseSeverity", "UNKNOWN").lower()
            cvss_vector = cvss.get("vectorString", "")
            break
            
    # Dates
    published = cve_metadata.get("datePublished", "")
    modified = cve_metadata.get("dateUpdated", "")
    
    # References
    refs = cna.get("references", [])
    ref_urls = [r.get("url", "") for r in refs[:5] if "url" in r]
    
    # Products / CPEs (approximation, since CPEs aren't strictly in v5 unless added)
    cpes = []
    affected = cna.get("affected", [])
    for aff in affected:
        vendor = aff.get("vendor", "*").replace(" ", "_").lower()
        product = aff.get("product", "*").replace(" ", "_").lower()
        
        if vendor == "n/a" or vendor == "unknown":
            vendor = "*"
        if product == "n/a" or product == "unknown":
            product = "*"
            
        # Add synthetic CPE for matching purposes
        synthetic_cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*"
        if synthetic_cpe not in cpes:
            cpes.append(synthetic_cpe)
        
    return {
        "cve_id": cve_id,
        "description": desc_en,
        "severity": severity,
        "score": score,
        "cvss_vector": cvss_vector,
        "published": published,
        "modified": modified,
        "references": ref_urls,
        "status": status,
        "cpes": cpes,
        "fetched_at": datetime.now(timezone.utc),
        "cached": True
    }

def main():
    parser = argparse.ArgumentParser(description="Import cvelistV5 data into NexShield")
    parser.add_argument("--repo", type=str, default=r"j:\PROGRAM\NexShield\cvelistV5-main\cvelistV5-main", help="Path to cvelistV5-main")
    parser.add_argument("--years", type=str, default="2022,2023,2024,2025,2026", help="Comma separated years to import, or 'all'")
    args = parser.parse_args()

    if not check_connection():
        print("Database connection failed. Exiting.")
        return

    base_dir = Path(args.repo) / "cves"
    if not base_dir.exists():
        print(f"Error: Directory {base_dir} not found.")
        return

    years = args.years.split(",")
    if "all" in [y.lower() for y in years]:
        year_dirs = [d for d in base_dir.iterdir() if d.is_dir() and d.name.isdigit()]
    else:
        year_dirs = [base_dir / y for y in years if (base_dir / y).exists()]

    total_inserted = 0
    batch_size = 1000
    batch = []

    print("Pre-fetching existing CVE IDs to optimize import...")
    existing_records = list(cve_cache.find({}))
    existing_cves = {record.get("cve_id") for record in existing_records if record.get("cve_id")}
    print(f"Found {len(existing_cves)} existing records.")

    print(f"Starting import from {base_dir}")
    
    for year_dir in year_dirs:
        print(f"Processing year: {year_dir.name}")
        for chunk_dir in year_dir.iterdir():
            if not chunk_dir.is_dir():
                continue
            for json_file in chunk_dir.glob("*.json"):
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    parsed = parse_v5_cve(data)
                    if parsed:
                        # Avoid duplicates using O(1) set lookup
                        cve_id = parsed["cve_id"]
                        if cve_id not in existing_cves:
                            batch.append(parsed)
                            existing_cves.add(cve_id)
                        
                        if len(batch) >= batch_size:
                            cve_cache.insert_many(batch)
                            total_inserted += len(batch)
                            batch.clear()
                            print(f"  Inserted {total_inserted} records...")
                except Exception as e:
                    print(f"Error processing {json_file}: {e}")

    # Insert remaining
    if batch:
        cve_cache.insert_many(batch)
        total_inserted += len(batch)

    print(f"Import complete! Total inserted: {total_inserted}")

if __name__ == "__main__":
    main()

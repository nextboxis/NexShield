#!/usr/bin/env python3
"""
scripts/import_ip_location.py — IP Geolocation & ASN Dataset Synchronizer
Downloads, parses, and updates local IP-to-Country and IP-to-ASN databases
from the official sapics/ip-location-db project.
"""

import os
import sys
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path for config access if needed
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

DATA_DIR = _ROOT / "data" / "ip_location"

RELEASE_BASE = "https://github.com/sapics/ip-location-db/releases/download/latest"

DATASETS = {
    "country": {
        "url": f"{RELEASE_BASE}/geolite2-country-ipv4-num.csv",
        "alt_url": f"{RELEASE_BASE}/dbip-country-ipv4-num.csv",
        "filename": "country-ipv4-num.csv",
        "desc": "IPv4 Country (Numeric range format: start_int,end_int,country_code)",
    },
    "asn": {
        "url": f"{RELEASE_BASE}/dbip-asn-ipv4.csv",
        "alt_url": f"{RELEASE_BASE}/geolite2-asn-ipv4.csv",
        "filename": "asn-ipv4.csv",
        "desc": "IPv4 ASN (Format: start_ip,end_ip,asn,as_name)",
    },
}


def download_file(url: str, dest_path: Path, alt_url: str = None) -> bool:
    """Download a file with streaming progress and fallback URL."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dest_path.with_suffix(".tmp")
    
    headers = {"User-Agent": "NexShield-Dataset-Updater/1.0"}
    target_urls = [url]
    if alt_url:
        target_urls.append(alt_url)

    for current_url in target_urls:
        print(f"[*] Downloading: {current_url}")
        try:
            req = urllib.request.Request(current_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp, open(temp_path, "wb") as out_f:
                total_size = int(resp.headers.get("content-length", 0))
                downloaded = 0
                block_size = 1024 * 64

                while True:
                    chunk = resp.read(block_size)
                    if not chunk:
                        break
                    out_f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        mb = downloaded / (1024 * 1024)
                        total_mb = total_size / (1024 * 1024)
                        sys.stdout.write(f"\r    Progress: {mb:.1f}/{total_mb:.1f} MB ({percent:.1f}%)")
                        sys.stdout.flush()
                    else:
                        mb = downloaded / (1024 * 1024)
                        sys.stdout.write(f"\r    Downloaded: {mb:.1f} MB")
                        sys.stdout.flush()

                print()

            # Atomically replace destination file
            if temp_path.exists():
                if dest_path.exists():
                    dest_path.unlink()
                temp_path.rename(dest_path)
            print(f"[+] Successfully saved to: {dest_path}")
            return True

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"\n[-] Download failed for {current_url}: {exc}")
            if temp_path.exists():
                temp_path.unlink()

    return False


def print_dataset_stats(data_dir: Path = DATA_DIR):
    """Print statistics of installed local datasets."""
    print("=" * 60)
    print("  NexShield IP Geolocation & ASN Dataset Status")
    print("=" * 60)
    print(f"Data Directory: {data_dir.resolve()}\n")

    for key, info in DATASETS.items():
        file_path = data_dir / info["filename"]
        if file_path.exists():
            size_mb = file_path.stat().st_size / (1024 * 1024)
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Count records (lines)
            line_count = 0
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in f:
                    line_count += 1

            print(f"[{key.upper()}] Installed:")
            print(f"    File:      {info['filename']}")
            print(f"    Size:      {size_mb:.2f} MB ({line_count:,} ranges)")
            print(f"    Modified:  {mtime}")
            print(f"    Desc:      {info['desc']}\n")
        else:
            print(f"[{key.upper()}] NOT INSTALLED:")
            print(f"    File:      {info['filename']}")
            print(f"    Desc:      {info['desc']}\n")


def create_starter_dataset(data_dir: Path = DATA_DIR):
    """
    Create a curated starter dataset if full files are not yet downloaded.
    Covers major cloud providers, CDNs, public DNS, and global internet hubs.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    country_file = data_dir / "country-ipv4-num.csv"
    asn_file = data_dir / "asn-ipv4.csv"

    # Starter country ranges (integer start, integer end, country)
    starter_countries = [
        # 1.0.0.0 - 1.0.0.255 (Cloudflare Australia)
        (16777216, 16777471, "AU"),
        # 1.1.1.0 - 1.1.1.255 (Cloudflare Australia/US)
        (16843008, 16843263, "AU"),
        # 8.8.4.0 - 8.8.8.255 (Google US)
        (134743040, 134744319, "US"),
        # 9.9.9.0 - 9.9.9.255 (Quad9 US)
        (151587072, 151587327, "US"),
        # 13.64.0.0 - 13.107.255.255 (Microsoft Azure US)
        (222298112, 225181695, "US"),
        # 20.0.0.0 - 20.255.255.255 (Microsoft US)
        (335544320, 352321535, "US"),
        # 52.0.0.0 - 52.255.255.255 (Amazon AWS US)
        (872415232, 889192447, "US"),
        # 54.0.0.0 - 54.255.255.255 (Amazon AWS US)
        (905969664, 922746879, "US"),
        # 104.16.0.0 - 104.31.255.255 (Cloudflare US)
        (1745879040, 1746927615, "US"),
        # 140.82.112.0 - 140.82.127.255 (GitHub / Fastly US)
        (2354212864, 2354216959, "US"),
        # 151.101.0.0 - 151.101.255.255 (Fastly CDN US)
        (2540044288, 2540109823, "US"),
        # 185.199.108.0 - 185.199.111.255 (GitHub Pages US)
        (3116887040, 3116888063, "US"),
    ]

    # Starter ASN ranges (start_ip, end_ip, asn, as_name)
    starter_asns = [
        ("1.0.0.0", "1.0.0.255", 13335, "Cloudflare, Inc."),
        ("1.1.1.0", "1.1.1.255", 13335, "Cloudflare, Inc."),
        ("8.8.4.0", "8.8.4.255", 15169, "Google LLC"),
        ("8.8.8.0", "8.8.8.255", 15169, "Google LLC"),
        ("9.9.9.0", "9.9.9.255", 19281, "QUAD9 - Quad9"),
        ("13.64.0.0", "13.107.255.255", 8075, "Microsoft Corporation"),
        ("20.0.0.0", "20.255.255.255", 8075, "Microsoft Corporation"),
        ("52.0.0.0", "52.255.255.255", 16509, "Amazon.com, Inc."),
        ("54.0.0.0", "54.255.255.255", 16509, "Amazon.com, Inc."),
        ("104.16.0.0", "104.31.255.255", 13335, "Cloudflare, Inc."),
        ("140.82.112.0", "140.82.127.255", 36459, "GitHub, Inc."),
        ("151.101.0.0", "151.101.255.255", 54113, "Fastly, Inc."),
        ("185.199.108.0", "185.199.111.255", 36459, "GitHub, Inc."),
    ]

    if not country_file.exists():
        print(f"[*] Initializing starter country dataset at: {country_file}")
        with open(country_file, "w", encoding="utf-8") as f:
            for start_i, end_i, cc in sorted(starter_countries):
                f.write(f"{start_i},{end_i},{cc}\n")

    if not asn_file.exists():
        print(f"[*] Initializing starter ASN dataset at: {asn_file}")
        with open(asn_file, "w", encoding="utf-8") as f:
            for s_ip, e_ip, asn, name in starter_asns:
                f.write(f'{s_ip},{e_ip},{asn},"{name}"\n')


def main():
    parser = argparse.ArgumentParser(description="Synchronize sapics/ip-location-db datasets into NexShield.")
    parser.add_argument("--download", action="store_true", help="Download latest full datasets from GitHub releases.")
    parser.add_argument("--force", action="store_true", help="Force redownload even if files exist.")
    parser.add_argument("--init-starter", action="store_true", help="Initialize lightweight starter dataset if empty.")
    parser.add_argument("--stats", action="store_true", help="Display status of installed datasets.")
    parser.add_argument("--target-dir", type=str, default=str(DATA_DIR), help="Custom target directory.")
    args = parser.parse_args()

    target_dir = Path(args.target_dir)

    if args.init_starter or (not args.download and not args.stats):
        create_starter_dataset(target_dir)
        print_dataset_stats(target_dir)

    if args.download:
        print("[*] Downloading latest datasets from sapics/ip-location-db...")
        for key, info in DATASETS.items():
            dest = target_dir / info["filename"]
            if dest.exists() and not args.force:
                print(f"[!] File already exists: {dest} (use --force to overwrite)")
                continue
            download_file(info["url"], dest, info.get("alt_url"))
        print_dataset_stats(target_dir)

    elif args.stats:
        print_dataset_stats(target_dir)


if __name__ == "__main__":
    main()

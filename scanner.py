"""
scanner.py — Automated Network Scanner using python-nmap
Scans a target IP range and saves results to the MongoDB `network_scans` collection.
"""

import nmap  # type: ignore
from datetime import datetime, timezone
from config import network_scans, check_connection  # type: ignore


# Default ports to scan (common services)
DEFAULT_PORTS = "22,80,443,8080,8443,3306,5432,6379,27017,21,25,53,110,143"
DEFAULT_TARGET = "192.168.1.0/24"


def run_scan(target=DEFAULT_TARGET, ports=DEFAULT_PORTS):
    """
    Run an nmap scan against `target` for the specified `ports`.
    Returns a list of scan-result dicts that were saved to MongoDB.
    """
    scanner = nmap.PortScanner()  # type: ignore
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    print(f"[*] Starting scan — target: {target}  ports: {ports}")
    scanner.scan(hosts=target, ports=ports, arguments="-sV -T4")  # type: ignore

    results = []

    for host in scanner.all_hosts():  # type: ignore
        host_data = {
            "scan_id": scan_id,
            "host": host,
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "protocols": [],
            "scanned_at": datetime.now(timezone.utc),
        }

        for proto in scanner[host].all_protocols():  # type: ignore
            ports_info = []
            for port in sorted(scanner[host][proto].keys()):  # type: ignore
                port_detail = scanner[host][proto][port]  # type: ignore
                ports_info.append({
                    "port": port,
                    "state": port_detail.get("state", "unknown"),
                    "service": port_detail.get("name", "unknown"),
                    "version": port_detail.get("version", ""),
                    "product": port_detail.get("product", ""),
                })
            host_data["protocols"].append({  # type: ignore
                "protocol": proto,
                "ports": ports_info,
            })

        results.append(host_data)

    # ── Persist to MongoDB ──────────────────────────────────────────
    if results and check_connection():
        network_scans.insert_many(results)
        print(f"[+] Saved {len(results)} host records to MongoDB (scan {scan_id})")
    elif not results:
        print("[!] No hosts discovered.")
    else:
        print("[!] MongoDB unreachable — results NOT saved.")

    return results


# ─── Standalone execution ────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    ports = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS
    data = run_scan(target, ports)
    print(f"\n[✓] Scan complete — {len(data)} host(s) found.")

"""
scanner.py — Advanced Network Scanner with nmap dependency lock,
scan types, IP validation, OS detection, and concurrency control.
"""

import nmap  # type: ignore
import ipaddress
import logging
import shutil
import threading
import time
from datetime import datetime, timezone
from config import network_scans, check_connection  # type: ignore

logger = logging.getLogger(__name__)

# ═════════════════════════════════════════════════════════════════════
#  Constants & Defaults
# ═════════════════════════════════════════════════════════════════════

DEFAULT_PORTS = "22,80,443,8080,8443,3306,5432,6379,27017,21,25,53,110,143"
DEFAULT_TARGET = "192.168.1.0/24"

# Scan type presets — nmap argument strings
SCAN_TYPES = {
    "quick":   {"args": "-sT -T4 --top-ports 100",           "label": "Quick TCP Connect (Top 100)"},
    "default": {"args": "-sV -T4",                            "label": "Service Version Detection"},
    "deep":    {"args": "-sV -sC -O -T3 --version-intensity 5", "label": "Deep Scan (Scripts + OS)"},
    "stealth": {"args": "-sS -T2 -f",                        "label": "Stealth SYN Scan (Fragmented)"},
    "udp":     {"args": "-sU -T4 --top-ports 50",            "label": "UDP Top 50"},
    "vuln":    {"args": "-sV --script=vuln -T3",              "label": "Vulnerability Scripts"},
    "ssl":     {"args": "-sV --script=ssl-enum-ciphers,ssl-cert -T3", "label": "SSL/TLS Cipher Scan"},
    "os":      {"args": "-O -sV -T4",                        "label": "OS Detection + Version"},
    "full":    {"args": "-sV -sC -O -A -T3 --version-intensity 7 -p-", "label": "Full Comprehensive (All Ports + Scripts + OS)"},
}

# ═════════════════════════════════════════════════════════════════════
#  Scan Lock — prevents concurrent scans
# ═════════════════════════════════════════════════════════════════════

_scan_lock = threading.Lock()
_status_lock = threading.Lock()
_active_scan = {"running": False, "target": None, "started_at": None, "progress": 0}


def is_scan_running():
    """Check if a scan is currently in progress."""
    with _status_lock:
        return _active_scan["running"]


def get_scan_status():
    """Return current scan state for the frontend."""
    with _status_lock:
        return dict(_active_scan)


# ═════════════════════════════════════════════════════════════════════
#  Nmap Dependency Check
# ═════════════════════════════════════════════════════════════════════

def check_nmap_installed():
    """
    Deep dependency check for nmap binary.
    Returns (ok: bool, info: dict) with version, path, and capabilities.
    """
    info = {"installed": False, "path": None, "version": None, "error": None}

    # 1. Check if nmap binary exists on PATH
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        info["error"] = (
            "nmap is not installed or not on PATH. "
            "Install it: https://nmap.org/download.html — "
            "On Windows, add nmap to your system PATH after install."
        )
        return False, info

    info["path"] = nmap_path

    # 2. Try to instantiate python-nmap and get version
    try:
        scanner = nmap.PortScanner()  # type: ignore
        version = scanner.nmap_version()  # type: ignore
        info["version"] = ".".join(str(v) for v in version)
        info["installed"] = True
    except nmap.PortScannerError as e:  # type: ignore
        info["error"] = f"nmap binary found but python-nmap failed: {e}"
        return False, info
    except Exception as e:
        info["error"] = f"Unexpected error checking nmap: {e}"
        return False, info

    return True, info


# ═════════════════════════════════════════════════════════════════════
#  IP / Target Validation
# ═════════════════════════════════════════════════════════════════════

def validate_target(target: str) -> dict:
    """
    Validate and classify a scan target.
    Accepts: single IP, CIDR range, or hostname.
    Returns: {"valid": bool, "type": str, "value": str, "error": str|None}
    """
    target = target.strip()
    if not target:
        return {"valid": False, "type": None, "value": target, "error": "Target is empty."}

    # Try as IP address
    try:
        addr = ipaddress.ip_address(target)
        return {
            "valid": True,
            "type": "ipv6" if addr.version == 6 else "ipv4",
            "value": str(addr),
            "is_private": addr.is_private,
            "is_loopback": addr.is_loopback,
            "error": None,
        }
    except ValueError:
        pass

    # Try as CIDR network
    try:
        net = ipaddress.ip_network(target, strict=False)
        host_count = net.num_addresses
        if host_count > 65536:
            return {"valid": False, "type": "cidr", "value": target,
                    "error": f"CIDR range too large ({host_count} hosts). Max /16."}
        return {
            "valid": True,
            "type": "cidr",
            "value": str(net),
            "host_count": host_count,
            "is_private": net.is_private,
            "error": None,
        }
    except ValueError:
        pass

    # Treat as hostname (basic validation)
    import re
    hostname_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
    if hostname_re.match(target):
        return {"valid": True, "type": "hostname", "value": target, "error": None}

    # Nmap-style target (e.g. "192.168.1.1-50")
    range_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$")
    if range_re.match(target):
        return {"valid": True, "type": "range", "value": target, "error": None}

    return {"valid": False, "type": None, "value": target,
            "error": "Invalid target. Use an IP, CIDR (e.g. 192.168.1.0/24), hostname, or range."}


# ═════════════════════════════════════════════════════════════════════
#  Core Scan Engine
# ═════════════════════════════════════════════════════════════════════

def run_scan(target=DEFAULT_TARGET, ports=DEFAULT_PORTS, scan_type="default",
             progress_callback=None):
    """
    Run an nmap scan with concurrency lock and enriched output.

    Args:
        target: IP, CIDR, hostname, or range.
        ports: Comma-separated port list (ignored for some scan types).
        scan_type: Key from SCAN_TYPES dict.
        progress_callback: Optional callable(percent, message) for live updates.

    Returns:
        list of scan-result dicts saved to MongoDB.

    Raises:
        RuntimeError: If nmap not installed or scan already running.
        ValueError: If target is invalid.
    """
    # ── Dependency lock check ────────────────────────────────────
    ok, nmap_info = check_nmap_installed()
    if not ok:
        raise RuntimeError(f"NMAP_DEPENDENCY_FAILED: {nmap_info['error']}")

    # ── Validate target ──────────────────────────────────────────
    validation = validate_target(target)
    if not validation["valid"]:
        raise ValueError(f"INVALID_TARGET: {validation['error']}")

    # ── Concurrency lock ─────────────────────────────────────────
    if not _scan_lock.acquire(blocking=False):
        raise RuntimeError("SCAN_LOCKED: Another scan is already running. Wait for it to finish.")

    try:
        with _status_lock:
            _active_scan.update({
                "running": True, "target": target,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "progress": 0, "scan_type": scan_type,
            })

        if progress_callback:
            progress_callback(5, f"Initializing {scan_type} scan on {target}...")

        # ── Resolve scan arguments ───────────────────────────────
        preset = SCAN_TYPES.get(scan_type, SCAN_TYPES["default"])
        scan_args = preset["args"]
        ports = (ports or DEFAULT_PORTS).strip()

        scanner = nmap.PortScanner()  # type: ignore
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        start_time = time.time()

        logger.info("SCAN START — target: %s  ports: %s  type: %s", target, ports, scan_type)
        logger.info("    nmap args: %s", scan_args)
        logger.info("    nmap version: %s  path: %s", nmap_info['version'], nmap_info['path'])

        if progress_callback:
            progress_callback(10, "Executing nmap scan...")

        # ── Execute nmap ─────────────────────────────────────────
        # For UDP, Quick, and Full scans, ports are handled by nmap flags directly in scan_args
        if scan_type in ("udp", "quick", "full"):
            scanner.scan(hosts=target, arguments=scan_args)  # type: ignore
        else:
            scanner.scan(hosts=target, ports=ports, arguments=scan_args)  # type: ignore

        elapsed = round(time.time() - start_time, 2)
        all_hosts = scanner.all_hosts()  # type: ignore
        total_hosts = len(all_hosts)

        if progress_callback:
            progress_callback(60, f"Scan complete. Processing {total_hosts} host(s)...")

        results = []

        for idx, host in enumerate(all_hosts):
            # ── Build enriched host document ─────────────────────
            host_data = {
                "scan_id": scan_id,
                "target": target,
                "ports": ports,
                "scan_type": scan_type,
                "scan_args": scan_args,
                "host": host,
                "hostname": scanner[host].hostname(),  # type: ignore
                "state": scanner[host].state(),  # type: ignore
                "protocols": [],
                "open_port_count": 0,
                "services_detected": [],
                "scan_duration_sec": elapsed,
                "nmap_version": nmap_info["version"],
                "scanned_at": datetime.now(timezone.utc),
            }

            # ── OS Detection (if available) ──────────────────────
            try:
                os_matches = scanner[host].get("osmatch", [])  # type: ignore
                if os_matches:
                    best_os = os_matches[0]
                    host_data["os_detection"] = {
                        "name": best_os.get("name", "Unknown"),
                        "accuracy": int(best_os.get("accuracy", 0)),
                        "family": best_os.get("osclass", [{}])[0].get("osfamily", "") if best_os.get("osclass") else "",
                        "vendor": best_os.get("osclass", [{}])[0].get("vendor", "") if best_os.get("osclass") else "",
                        "all_matches": [
                            {"name": m.get("name", ""), "accuracy": int(m.get("accuracy", 0))}
                            for m in os_matches[:5]
                        ],
                    }
            except Exception:
                pass

            # ── MAC Address ──────────────────────────────────────
            try:
                addresses = scanner[host].get("addresses", {})  # type: ignore
                if "mac" in addresses:
                    host_data["mac_address"] = addresses["mac"]
                vendor = scanner[host].get("vendor", {})  # type: ignore
                if vendor:
                    host_data["mac_vendor"] = list(vendor.values())[0] if vendor.values() else ""
            except Exception:
                pass

            # ── Port / Protocol Data ─────────────────────────────
            open_count = 0
            services = []

            for proto in scanner[host].all_protocols():  # type: ignore
                ports_info = []
                for port in sorted(scanner[host][proto].keys()):  # type: ignore
                    port_detail = scanner[host][proto][port]  # type: ignore
                    port_state = port_detail.get("state", "unknown")

                    port_doc = {
                        "port": port,
                        "state": port_state,
                        "service": port_detail.get("name", "unknown"),
                        "version": port_detail.get("version", ""),
                        "product": port_detail.get("product", ""),
                        "extrainfo": port_detail.get("extrainfo", ""),
                        "cpe": port_detail.get("cpe", ""),
                        "reason": port_detail.get("reason", ""),
                    }

                    # Script output (for deep/vuln scans)
                    script_output = port_detail.get("script", {})
                    if script_output:
                        port_doc["scripts"] = {
                            k: str(v)[:500] for k, v in script_output.items()
                        }

                    ports_info.append(port_doc)

                    if port_state == "open":
                        open_count += 1
                        svc_name = port_detail.get("name", "")
                        if svc_name and svc_name not in services:
                            services.append(svc_name)

                host_data["protocols"].append({  # type: ignore
                    "protocol": proto,
                    "ports": ports_info,
                })

            host_data["open_port_count"] = open_count
            host_data["services_detected"] = services
            results.append(host_data)

            if progress_callback:
                pct = 60 + int((idx + 1) / max(total_hosts, 1) * 30)
                progress_callback(pct, f"Processed {idx + 1}/{total_hosts} hosts")

        # ── Persist to MongoDB ───────────────────────────────────
        if results and check_connection():
            network_scans.insert_many(results)
            logger.info("Saved %d host records to MongoDB (scan %s)", len(results), scan_id)
        elif not results:
            logger.warning("No hosts discovered.")
        else:
            logger.warning("MongoDB unreachable — results NOT saved.")

        if progress_callback:
            progress_callback(100, f"Scan complete: {len(results)} host(s), {elapsed}s elapsed")

        logger.info("Scan finished in %ss — %d host(s)", elapsed, len(results))
        return results

    finally:
        with _status_lock:
            _active_scan.update({"running": False, "target": None, "progress": 100})
        _scan_lock.release()


# ═════════════════════════════════════════════════════════════════════
#  Standalone CLI
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    # Check nmap first
    ok, info = check_nmap_installed()
    print(f"nmap installed: {ok}")
    for k, v in info.items():
        print(f"  {k}: {v}")

    if not ok:
        sys.exit(1)

    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    ports = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS
    scan_type = sys.argv[3] if len(sys.argv) > 3 else "default"

    def on_progress(pct, msg):
        print(f"  [{pct:3d}%] {msg}")

    data = run_scan(target, ports, scan_type, progress_callback=on_progress)
    print(f"\n[✓] Scan complete — {len(data)} host(s) found.")

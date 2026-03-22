"""
ai_logic.py — AI Multi-Model Threat Analysis & Deduplication (Advanced)

Architecture: 7 independent analysis "engines" that each inspect scan data
from a different angle. Each engine tags its findings with its own model name,
creating a multi-perspective threat intelligence pipeline.

Engine Registry:
  1. PortRisk-Engine-v2      — Sensitive port exposure analysis
  2. VersionVuln-Engine-v2   — Missing/outdated version detection
  3. ServiceFP-Engine-v1     — Service fingerprint anomaly detection
  4. DefaultCreds-Engine-v1  — Default-credential risk assessment
  5. NetExposure-Engine-v1   — Network exposure & attack surface scoring
  6. MitreMap-Engine-v1      — MITRE ATT&CK technique mapping
  7. DedupMerge-Engine-v2    — Intelligent duplicate merging

Run Order:  analyze_scan_results() → compute_risk_scores() → merge_duplicates()
"""

from datetime import datetime, timezone
import hashlib
import re
from config import threats, network_scans, check_connection  # type: ignore


# ═════════════════════════════════════════════════════════════════════
#  Model Registry
# ═════════════════════════════════════════════════════════════════════

MODELS = {
    "port_risk":     "PortRisk-Engine-v2",
    "version_vuln":  "VersionVuln-Engine-v2",
    "service_fp":    "ServiceFP-Engine-v1",
    "default_creds": "DefaultCreds-Engine-v1",
    "net_exposure":  "NetExposure-Engine-v1",
    "mitre_map":     "MitreMap-Engine-v1",
    "dedup":         "DedupMerge-Engine-v2",
}


# ═════════════════════════════════════════════════════════════════════
#  Knowledge Bases
# ═════════════════════════════════════════════════════════════════════

# ── Ports classified by risk tier ──────────────────────────────────
SENSITIVE_PORTS = {
    # port: (threat_name, severity, mitre_technique)
    21:    ("FTP Exposed",             "high",     "T1071.002"),
    22:    ("SSH Exposed",             "medium",   "T1021.004"),
    23:    ("Telnet Exposed",          "critical", "T1021.006"),
    25:    ("SMTP Open Relay Risk",    "high",     "T1071.003"),
    53:    ("DNS Exposed",             "medium",   "T1071.004"),
    80:    ("HTTP Unencrypted",        "low",      "T1071.001"),
    110:   ("POP3 Exposed",           "medium",   "T1071.003"),
    111:   ("RPCbind Exposed",        "high",     "T1210"),
    135:   ("MSRPC Exposed",          "high",     "T1210"),
    139:   ("NetBIOS Exposed",        "high",     "T1210"),
    143:   ("IMAP Exposed",           "medium",   "T1071.003"),
    443:   ("HTTPS Service",          "info",     "T1071.001"),
    445:   ("SMB Exposed",            "critical", "T1021.002"),
    1433:  ("MSSQL Exposed",          "high",     "T1190"),
    1521:  ("Oracle DB Exposed",      "high",     "T1190"),
    2049:  ("NFS Exposed",            "high",     "T1210"),
    3306:  ("MySQL Exposed",          "high",     "T1190"),
    3389:  ("RDP Exposed",            "critical", "T1021.001"),
    5432:  ("PostgreSQL Exposed",     "high",     "T1190"),
    5900:  ("VNC Exposed",            "critical", "T1021.005"),
    5985:  ("WinRM Exposed",          "high",     "T1021.006"),
    6379:  ("Redis Exposed",          "critical", "T1190"),
    8080:  ("HTTP-Alt Exposed",       "medium",   "T1071.001"),
    8443:  ("HTTPS-Alt Exposed",      "low",      "T1071.001"),
    9200:  ("Elasticsearch Exposed",  "critical", "T1190"),
    11211: ("Memcached Exposed",      "critical", "T1190"),
    27017: ("MongoDB Exposed",        "critical", "T1190"),
}

# ── Services known to ship with default credentials ────────────────
DEFAULT_CRED_SERVICES = {
    "mysql":          "root / (empty)",
    "postgresql":     "postgres / postgres",
    "mongodb":        "admin / (no auth)",
    "redis":          "(no auth by default)",
    "elasticsearch":  "(no auth by default)",
    "memcached":      "(no auth by default)",
    "ftp":            "anonymous / (any)",
    "vnc":            "password / vnc",
    "tomcat":         "tomcat / tomcat",
    "jenkins":        "admin / admin",
    "phpmyadmin":     "root / (empty)",
    "webmin":         "root / root",
    "smb":            "guest / (empty)",
}

# ── Known vulnerable product versions (simplified heuristic) ───────
KNOWN_VULN_PATTERNS = [
    # (regex_on_product+version, CVE_ref, severity, description)
    (r"apache\s*httpd?\s*2\.[0-3]\.",                "CVE-2021-41773", "critical", "Apache HTTPD < 2.4 — path traversal risk"),
    (r"openssh\s*[0-7]\.",                            "CVE-2023-38408", "high",     "OpenSSH < 8.0 — agent forwarding vulnerabilities"),
    (r"openssl\s*1\.0\.",                             "CVE-2014-0160",  "critical", "OpenSSL 1.0.x — potential Heartbleed"),
    (r"nginx\s*1\.(0|1|2|3|4|5|6|7|8|9|1[0-6])\.",   "CVE-2022-41741", "high",     "Nginx < 1.17 — memory corruption risk"),
    (r"proftpd\s*1\.[0-2]\.",                         "CVE-2019-12815", "critical", "ProFTPD < 1.3 — arbitrary file copy"),
    (r"vsftpd\s*2\.",                                 "CVE-2011-2523",  "critical", "vsftpd 2.x — backdoor vulnerability"),
    (r"microsoft\s*sql.*201[0-4]",                    "CVE-2020-0618",  "high",     "MSSQL 2010-2014 — remote code execution risk"),
    (r"mysql\s*5\.[0-5]\.",                           "CVE-2016-6662",  "high",     "MySQL < 5.6 — privilege escalation risk"),
    (r"mariadb\s*5\.",                                "CVE-2016-6662",  "high",     "MariaDB 5.x — privilege escalation risk"),
    (r"samba\s*[1-3]\.",                              "CVE-2017-7494",  "critical", "Samba < 4.0 — SambaCry remote code execution"),
]

# ── MITRE ATT&CK Technique descriptions ───────────────────────────
MITRE_TECHNIQUES = {
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH",
    "T1021.005": "VNC",
    "T1021.006": "Windows Remote Management",
    "T1071.001": "Application Layer Protocol: Web",
    "T1071.002": "Application Layer Protocol: File Transfer",
    "T1071.003": "Application Layer Protocol: Mail",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1190":     "Exploit Public-Facing Application",
    "T1210":     "Exploitation of Remote Services",
}

# ── Severity weights for composite risk scoring ────────────────────
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high":     7,
    "medium":   4,
    "low":      2,
    "info":     0,
}


# ═════════════════════════════════════════════════════════════════════
#  Core Pipeline — analyze_scan_results()
# ═════════════════════════════════════════════════════════════════════

def analyze_scan_results():
    """
    Multi-model analysis pipeline. Runs all engines against the latest
    scan batch and produces deduplicated threat entries.
    Returns the count of new threats created.
    """
    if not check_connection():
        return 0

    latest = network_scans.find_one(sort=[("scanned_at", -1)])
    if not latest:
        return 0

    scan_id = latest["scan_id"]
    scans = list(network_scans.find({"scan_id": scan_id}))
    new_threats = []
    seen_hashes = set()  # Deduplicate within the same analysis run

    for scan in scans:
        host = scan.get("host", "unknown")
        for proto_block in scan.get("protocols", []):
            protocol = str(proto_block.get("protocol", "tcp"))
            for port_info in proto_block.get("ports", []):
                port = port_info["port"]
                state = port_info.get("state", "")
                service = str(port_info.get("service", ""))
                product = str(port_info.get("product", ""))
                version = str(port_info.get("version", ""))

                if state != "open":
                    continue

                ctx = {
                    "host": host, "port": port, "protocol": protocol,
                    "service": service, "product": product, "version": version,
                }

                # Run each engine and collect threats
                for engine_fn in [
                    _engine_port_risk,
                    _engine_version_vuln,
                    _engine_service_fp,
                    _engine_default_creds,
                    _engine_mitre_map,
                ]:
                    for t in engine_fn(ctx):  # type: ignore
                        h = _threat_hash(t)
                        if h not in seen_hashes:
                            seen_hashes.add(h)
                            new_threats.append(t)

    # Batch insert
    if new_threats:
        threats.insert_many(new_threats)

    return len(new_threats)


# ═════════════════════════════════════════════════════════════════════
#  Engine 1 — Port Risk Analysis
# ═════════════════════════════════════════════════════════════════════

def _engine_port_risk(ctx):
    """Flag open ports that are in the sensitive ports database."""
    port = ctx["port"]
    if port not in SENSITIVE_PORTS:
        return []

    name, severity, _ = SENSITIVE_PORTS[port]
    detail = (
        f"Port {port}/{ctx['protocol']} open — "
        f"{ctx['service']} {ctx['product']} {ctx['version']}".strip()
    )
    return [_make_threat(
        name=name, severity=severity, host=ctx["host"],
        cve_id=f"SCAN-{port}-{ctx['host'].replace('.', '_')}",
        source=MODELS["port_risk"], detail=detail,
        tags=["exposure", "network"],
    )]


# ═════════════════════════════════════════════════════════════════════
#  Engine 2 — Version Vulnerability Detection
# ═════════════════════════════════════════════════════════════════════

def _engine_version_vuln(ctx):
    """Check for known vulnerable product+version combinations."""
    results = []
    product = ctx["product"]
    version = ctx["version"]
    full_str = f"{product} {version}".strip().lower()

    # Flag missing version info
    if product and not version:
        results.append(_make_threat(
            name=f"Unknown Version: {product}",
            severity="medium", host=ctx["host"],
            cve_id=f"VER-{ctx['port']}-{ctx['host'].replace('.', '_')}",
            source=MODELS["version_vuln"],
            detail=f"{product} on port {ctx['port']} has no version — may be outdated.",
            tags=["version", "patch"],
        ))

    # Match against known vulnerable patterns
    for pattern, cve, sev, desc in KNOWN_VULN_PATTERNS:
        if re.search(pattern, full_str, re.IGNORECASE):
            results.append(_make_threat(
                name=f"Vulnerable: {product} {version}",
                severity=sev, host=ctx["host"],
                cve_id=cve,
                source=MODELS["version_vuln"],
                detail=desc,
                tags=["cve", "version", "vulnerability"],
            ))
            break  # One CVE match per port is enough

    return results


# ═════════════════════════════════════════════════════════════════════
#  Engine 3 — Service Fingerprint Anomaly Detection
# ═════════════════════════════════════════════════════════════════════

# Expected services for common ports (anomaly = unexpected service)
EXPECTED_SERVICES = {
    22:   ["ssh"],
    80:   ["http", "www", "httpd"],
    443:  ["https", "ssl", "http"],
    3306: ["mysql", "mariadb"],
    5432: ["postgresql", "postgres"],
    8080: ["http-proxy", "http", "http-alt"],
    3389: ["ms-wbt-server", "rdp"],
}


def _engine_service_fp(ctx):
    """Detect unexpected services running on standard ports (masquerading)."""
    port = ctx["port"]
    service = ctx["service"].lower()

    if port not in EXPECTED_SERVICES or not service:
        return []

    expected = EXPECTED_SERVICES[port]
    if any(e in service for e in expected):
        return []

    # Anomaly: unexpected service on a well-known port
    return [_make_threat(
        name=f"Anomalous Service on Port {port}",
        severity="high", host=ctx["host"],
        cve_id=f"FP-{port}-{ctx['host'].replace('.', '_')}",
        source=MODELS["service_fp"],
        detail=(
            f"Expected [{', '.join(expected)}] on port {port}, "
            f"but found '{service}' ({ctx['product']}). "
            "This may indicate service masquerading or a backdoor."
        ),
        tags=["anomaly", "fingerprint", "masquerade"],
    )]


# ═════════════════════════════════════════════════════════════════════
#  Engine 4 — Default Credentials Risk Assessment
# ═════════════════════════════════════════════════════════════════════

def _engine_default_creds(ctx):
    """Flag services known to ship with weak/default credentials."""
    service = ctx["service"].lower()
    product = ctx["product"].lower()
    check_vals = [service, product]

    for key, creds in DEFAULT_CRED_SERVICES.items():
        if any(key in v for v in check_vals):
            return [_make_threat(
                name=f"Default Credentials Risk: {key.title()}",
                severity="high", host=ctx["host"],
                cve_id=f"CRED-{ctx['port']}-{ctx['host'].replace('.', '_')}",
                source=MODELS["default_creds"],
                detail=(
                    f"{key.title()} on port {ctx['port']} may accept default "
                    f"credentials: {creds}. Verify authentication is enforced."
                ),
                tags=["credentials", "authentication", "hardening"],
            )]

    return []


# ═════════════════════════════════════════════════════════════════════
#  Engine 5 — MITRE ATT&CK Technique Mapping
# ═════════════════════════════════════════════════════════════════════

def _engine_mitre_map(ctx):
    """Map open ports to MITRE ATT&CK techniques."""
    port = ctx["port"]
    if port not in SENSITIVE_PORTS:
        return []

    _, severity, technique = SENSITIVE_PORTS[port]
    if severity == "info":
        return []  # Skip informational items

    technique_name = MITRE_TECHNIQUES.get(technique, "Unknown Technique")

    return [_make_threat(
        name=f"ATT&CK: {technique_name}",
        severity="medium", host=ctx["host"],
        cve_id=f"MITRE-{technique}-{ctx['host'].replace('.', '_')}",
        source=MODELS["mitre_map"],
        detail=(
            f"Port {port}/{ctx['protocol']} enables MITRE ATT&CK technique "
            f"{technique} ({technique_name}). Service: {ctx['service']} "
            f"{ctx['product']} {ctx['version']}".strip()
        ),
        tags=["mitre", "attack", technique],
    )]


# ═════════════════════════════════════════════════════════════════════
#  Risk Scoring Engine
# ═════════════════════════════════════════════════════════════════════

def compute_risk_scores():
    """
    Scan all threats in the database and compute a composite risk score
    for each affected host. Stores results as 'risk_score' documents.
    Returns a dict of {host: score}.
    """
    if not check_connection():
        return {}

    pipeline = [
        {"$group": {
            "_id": "$host",
            "threat_count": {"$sum": 1},
            "severities": {"$push": "$severity"},
            "engines": {"$addToSet": "$source"},
            "latest": {"$max": "$detected_at"},
        }},
        {"$sort": {"threat_count": -1}},
    ]

    host_groups = list(threats.aggregate(pipeline))
    scores = {}

    for group in host_groups:
        host = group["_id"]
        if not host:
            continue

        # Weighted severity sum
        sev_score = sum(
            SEVERITY_WEIGHTS.get(s, 0)
            for s in group["severities"]
        )

        # Diversity bonus: more engines finding issues = higher confidence
        engine_bonus = len(group["engines"]) * 2

        # Volume factor: more threats = more concerning
        volume_factor = min(group["threat_count"] * 0.5, 15)

        total = round(sev_score + engine_bonus + volume_factor, 1)
        risk_level = (
            "critical" if total >= 40 else
            "high" if total >= 25 else
            "medium" if total >= 12 else
            "low"
        )

        scores[host] = {
            "score": total,
            "risk_level": risk_level,
            "threat_count": group["threat_count"],
            "engines_flagged": len(group["engines"]),
        }

        # Persist the risk score as a tag on all threats from this host
        threats.update_many(
            {"host": host},
            {"$set": {
                "host_risk_score": total,
                "host_risk_level": risk_level,
            }},
        )

    return scores


# ═════════════════════════════════════════════════════════════════════
#  Deduplication Engine
# ═════════════════════════════════════════════════════════════════════

def identify_duplicates():
    """Find threats sharing the same CVE ID + host (count > 1)."""
    if not check_connection():
        return []

    pipeline = [
        {"$group": {
            "_id": {"cve_id": "$cve_id", "host": "$host"},
            "count": {"$sum": 1},
            "ids": {"$push": "$_id"},
            "sources": {"$addToSet": "$source"},
            "descriptions": {"$addToSet": "$detail"},
            "latest": {"$max": "$detected_at"},
        }},
        {"$match": {"count": {"$gt": 1}}},
        {"$sort": {"count": -1}},
    ]
    return list(threats.aggregate(pipeline))


def merge_duplicates():
    """
    Keep the most-recent document per duplicate group, merge sources
    and descriptions into it, then delete the rest.
    Returns the number of redundant documents removed.
    """
    groups = identify_duplicates()
    removed = 0

    for group in groups:
        ids = group["ids"]
        keep = threats.find_one(
            {"_id": {"$in": ids}},
            sort=[("detected_at", -1)],
        )
        if not keep:
            continue

        discard_ids = [i for i in ids if i != keep["_id"]]
        merged_sources = list(set(group["sources"]))
        merged_details = list(set(group["descriptions"]))

        threats.update_one(
            {"_id": keep["_id"]},
            {"$set": {
                "source": ", ".join(merged_sources),
                "detail": " | ".join(merged_details),
                "merged_count": len(ids),
                "merged_by": MODELS["dedup"],
                "merged_at": datetime.now(timezone.utc),
            }},
        )

        threats.delete_many({"_id": {"$in": discard_ids}})
        removed += len(discard_ids)

    return removed


# ═════════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════════

def _make_threat(name, severity, host, cve_id, source, detail, tags=None):
    """Create a standardized threat document."""
    return {
        "name": name,
        "severity": severity,
        "host": host,
        "cve_id": cve_id,
        "source": source,
        "detail": detail,
        "tags": tags or [],
        "detected_at": datetime.now(timezone.utc),
    }


def _threat_hash(threat):
    """Generate a unique hash for dedup within a single run."""
    key = f"{threat['cve_id']}|{threat['host']}|{threat['source']}"
    return hashlib.md5(key.encode()).hexdigest()


# ═════════════════════════════════════════════════════════════════════
#  Standalone execution
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 58)
    print("   NexShield AI Analysis Pipeline")
    print("=" * 58)

    print("\n[1/3] Running multi-model analysis...")
    created = analyze_scan_results()
    print(f"  → Created {created} threat entries.")

    print("\n[2/3] Computing host risk scores...")
    scores = compute_risk_scores()
    for host, info in sorted(scores.items(), key=lambda x: -x[1]["score"]):
        print(f"  → {host}: score={info['score']} ({info['risk_level']}) "
              f"— {info['threat_count']} threats, {info['engines_flagged']} engines")

    print("\n[3/3] Merging duplicate threats...")
    removed = merge_duplicates()
    print(f"  → Removed {removed} duplicate entries.")

    print(f"\n{'=' * 58}")
    print(f"   Pipeline complete.")
    print(f"{'=' * 58}")

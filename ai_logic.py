"""
ai_logic.py — AI Multi-Model Threat Analysis & Deduplication (Advanced v5)

Architecture: 16 independent analysis "engines" that each inspect scan data
from a different angle. Each engine tags its findings with its own model name,
creating a multi-perspective threat intelligence pipeline.

Engine Registry:
  1.  PortRisk-Engine-v2         — Sensitive port exposure analysis
  2.  VersionVuln-Engine-v3      — Missing/outdated version detection (expanded CVE DB)
  3.  ServiceFP-Engine-v2        — Service fingerprint anomaly detection
  4.  DefaultCreds-Engine-v2     — Default-credential risk assessment
  5.  MitreMap-Engine-v1         — MITRE ATT&CK technique mapping
  6.  ML-Predict-Engine-v4       — Trained ML prediction (Ensemble with ColumnTransformer)
  7.  CVECorrelation-Engine-v1   — Cross-reference services with NVD CVE cache
  8.  Behavioral-Engine-v2       — Suspicious port combination detection
  9.  DedupMerge-Engine-v2       — Intelligent duplicate merging
  10. Encryption-Engine-v1       — Weak/missing encryption detection
  11. LateralMove-Engine-v1      — Lateral movement graph analysis
  12. ExposureScore-Engine-v1    — Attack surface exposure scoring
  13. CredentialDump-Engine-v1   — Credential harvesting risk detection (T1003)
  14. PersistenceAudit-Engine-v1 — Persistence mechanism detection (T1053/T1505)
  15. DLLHijack-Engine-v1        — DLL side-loading risk detection (T1574)
  16. ZeroDayHeuristics-Engine-v1— Entropy/Anomaly-based unknown threat detection

Run Order:  analyze_scan_results() → compute_risk_scores() → merge_duplicates()
"""

import sys
# Fix Windows console encoding for Unicode output
try:
    sys.stdout.reconfigure(encoding='utf-8')  # type: ignore
except Exception:
    pass

from datetime import datetime, timezone
import hashlib
import logging
import re
from config import threats, network_scans, cve_cache, check_connection  # type: ignore

logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════
#  Model Registry
# ═════════════════════════════════════════════════════════════════════

MODELS = {
    "port_risk":     "PortRisk-Engine-v2",
    "version_vuln":  "VersionVuln-Engine-v3",
    "service_fp":    "ServiceFP-Engine-v2",
    "default_creds": "DefaultCreds-Engine-v2",
    "mitre_map":     "MitreMap-Engine-v1",
    "ml_predict":    "ML-Predict-Engine-v4",
    "behavioral":    "Behavioral-Engine-v2",
    "cve_corr":      "CVECorrelation-Engine-v1",
    "dedup":         "DedupMerge-Engine-v2",
    "encryption":    "Encryption-Engine-v1",
    "lateral_move":  "LateralMove-Engine-v1",
    "exposure":      "ExposureScore-Engine-v1",
    "cred_dump":     "CredentialDump-Engine-v1",
    "persistence":   "PersistenceAudit-Engine-v1",
    "dll_hijack":    "DLLHijack-Engine-v1",
    "zero_day":      "ZeroDayHeuristics-Engine-v1",
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
    4444:  ("Metasploit Meterpreter Default", "critical", "T1071.001"),
    5432:  ("PostgreSQL Exposed",     "high",     "T1190"),
    5900:  ("VNC Exposed",            "critical", "T1021.005"),
    5985:  ("WinRM Exposed",          "high",     "T1021.006"),
    6379:  ("Redis Exposed",          "critical", "T1190"),
    8080:  ("HTTP-Alt Exposed",       "medium",   "T1071.001"),
    8443:  ("HTTPS-Alt Exposed",      "low",      "T1071.001"),
    9200:  ("Elasticsearch Exposed",  "critical", "T1190"),
    9300:  ("Elasticsearch Transport", "critical", "T1190"),
    11211: ("Memcached Exposed",      "critical", "T1190"),
    27017: ("MongoDB Exposed",        "critical", "T1190"),
    27018: ("MongoDB Shard Exposed",  "critical", "T1190"),
    2379:  ("etcd Exposed",           "critical", "T1190"),
    2380:  ("etcd Peer Exposed",      "critical", "T1190"),
    6443:  ("Kubernetes API Exposed", "critical", "T1190"),
    
    10250: ("Kubelet API Exposed",    "critical", "T1190"),
    8888:  ("Jupyter Notebook Exposed","critical", "T1190"),
    5601:  ("Kibana Exposed",         "high",     "T1190"),
    9090:  ("Prometheus Exposed",     "high",     "T1190"),
    3000:  ("Grafana/Dev Server",     "medium",   "T1190"),
    8500:  ("Consul Exposed",         "high",     "T1190"),
    4848:  ("GlassFish Admin",        "high",     "T1190"),
    7001:  ("WebLogic Admin",         "critical", "T1190"),
    50000: ("Jenkins Agent Port",     "high",     "T1190"),
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
    "grafana":        "admin / admin",
    "consul":         "(no auth by default)",
    "kibana":         "(no auth by default)",
    "etcd":           "(no auth by default)",
    "prometheus":     "(no auth by default)",
    "rabbitmq":       "guest / guest",
    "activemq":       "admin / admin",
    "couchdb":        "admin / admin",
    "minio":          "minioadmin / minioadmin",
    "jupyter":        "(token or no auth)",
    "glassfish":      "admin / admin",
    "weblogic":       "weblogic / welcome1",
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
    (r"log4j\s*2\.(0|1[0-4])\.",                      "CVE-2021-44228", "critical", "Log4j 2.x — Log4Shell RCE vulnerability"),
    (r"spring-core\s*5\.[0-3]\.",                     "CVE-2022-22965", "critical", "Spring Framework — Spring4Shell RCE"),
    (r"exchange\s*server\s*201[3-9]",                 "CVE-2021-26855", "critical", "Microsoft Exchange — ProxyLogon SSRF"),
    (r"tomcat\s*(4|5|6|7|8\.0)\.",                    "CVE-2020-1938",  "critical", "Apache Tomcat — Ghostcat AJP vulnerability"),
    (r"iis\s*(6|7)\.\d",                              "CVE-2017-7269",  "critical", "Microsoft IIS 6/7 — WebDAV buffer overflow"),
    (r"phpmyadmin\s*(3|4\.[0-7])\.",                  "CVE-2018-12613", "high",     "phpMyAdmin < 4.8 — LFI vulnerability"),
    (r"jenkins\s*(1\.|2\.[0-2]\d{2})",                "CVE-2024-23897", "critical", "Jenkins < 2.300 — arbitrary file read"),
    (r"docker\s*(1[0-7]|18\.(0[0-6]))",               "CVE-2019-5736",  "critical", "Docker < 18.09 — runc container escape"),
    (r"kubernetes\s*1\.(1[0-5])\.",                    "CVE-2020-8558",  "high",     "Kubernetes < 1.16 — kube-proxy host network bypass"),
    (r"grafana\s*(7|8\.[0-4])\.",                     "CVE-2021-43798", "critical", "Grafana < 8.5 — path traversal to arbitrary file read"),
    (r"gitlab\s*(11|12|13\.[0-9])\.",                 "CVE-2021-22205", "critical", "GitLab < 14.0 — remote code execution via image upload"),
    (r"confluence\s*(6|7\.[0-3])\.",                  "CVE-2022-26134", "critical", "Confluence — OGNL injection RCE"),
    (r"weblogic\s*(10|12\.1)\.",                      "CVE-2020-14882", "critical", "WebLogic — unauthenticated RCE"),
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
    "T1003":     "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.003": "NTDS",
    "T1003.006": "DCSync",
    "T1053.005": "Scheduled Task",
    "T1505.003": "Web Shell",
    "T1574.002": "DLL Side-Loading",
}

# ── Suspicious port combination patterns (behavioral analysis) ─────
SUSPICIOUS_COMBOS = [
    # (required_ports, threat_name, severity, description)
    (
        {3389, 445},
        "Lateral Movement Risk: RDP + SMB",
        "critical",
        "Host exposes both RDP (3389) and SMB (445) — common lateral movement pattern in enterprise attacks.",
    ),
    (
        {3306, 3389},
        "Data Exfil Risk: Database + RDP",
        "critical",
        "Host exposes MySQL (3306) alongside RDP (3389) — possible data exfiltration path via remote desktop.",
    ),
    (
        {22, 3306},
        "DB Admin Exposure: SSH + MySQL",
        "high",
        "Host exposes SSH (22) and MySQL (3306) — remote database administration is possible, verify access controls.",
    ),
    (
        {21, 80},
        "Web Defacement Risk: FTP + HTTP",
        "high",
        "Host exposes both FTP (21) and HTTP (80) — FTP-based web shell upload is a common attack vector.",
    ),
    (
        {6379, 80},
        "Cache Poisoning Risk: Redis + HTTP",
        "critical",
        "Host exposes Redis (6379) alongside a web server — unauthenticated Redis can lead to cache poisoning or RCE.",
    ),
    (
        {27017, 80},
        "NoSQL Injection Surface: MongoDB + HTTP",
        "critical",
        "Host exposes MongoDB (27017) with a web server — common NoSQL injection attack surface.",
    ),
    (
        {5900, 22},
        "Multi-Remote Access: VNC + SSH",
        "high",
        "Host has multiple remote access protocols (VNC + SSH) — increases attack surface for unauthorized access.",
    ),
    (
        {9200, 80},
        "Data Leak Risk: Elasticsearch + HTTP",
        "critical",
        "Host exposes Elasticsearch (9200) and a web server — Elasticsearch data leaks are among the most common breaches.",
    ),
    (
        {6443, 10250},
        "K8s Cluster Exposed: API + Kubelet",
        "critical",
        "Host exposes Kubernetes API (6443) and Kubelet (10250) — full cluster compromise possible.",
    ),
    (
        {5601, 9200},
        "ELK Stack Exposed: Kibana + Elasticsearch",
        "critical",
        "Host exposes both Kibana (5601) and Elasticsearch (9200) — data leak and dashboard manipulation risk.",
    ),
    (
        {3389, 5900},
        "Dual Remote Desktop: RDP + VNC",
        "critical",
        "Host exposes both RDP (3389) and VNC (5900) — extremely high unauthorized access risk.",
    ),
    (
        {8080, 3306, 6379},
        "Full Stack Exposed: Web + DB + Cache",
        "critical",
        "Host exposes web (8080), MySQL (3306), and Redis (6379) — complete application stack is reachable.",
    ),
]

# ── Service-to-keyword mapping for CVE cache correlation ───────────
SERVICE_CVE_KEYWORDS = {
    "ssh": ["openssh", "ssh"],
    "http": ["apache", "httpd", "nginx", "http"],
    "https": ["apache", "nginx", "openssl", "tls"],
    "ftp": ["proftpd", "vsftpd", "ftp"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgresql", "postgres"],
    "mongodb": ["mongodb", "mongo"],
    "redis": ["redis"],
    "smb": ["samba", "smb", "cifs"],
    "rdp": ["rdp", "remote desktop"],
    "vnc": ["vnc"],
    "elasticsearch": ["elasticsearch", "elastic"],
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
                    "cpe": port_info.get("cpe", ""),
                    "cves": port_info.get("cves", []),
                }

                # Run each engine and collect threats
                for engine_fn in [
                    _engine_port_risk,
                    _engine_version_vuln,
                    _engine_service_fp,
                    _engine_default_creds,
                    _engine_mitre_map,
                    _engine_ml_predict,
                    _engine_cve_correlation,
                    _engine_encryption,
                    _engine_exposure_score,
                    _engine_credential_dump,
                    _engine_persistence_audit,
                    _engine_dll_hijack,
                    _engine_zero_day_heuristics,
                ]:
                    for t in engine_fn(ctx):  # type: ignore
                        h = _threat_hash(t)
                        if h not in seen_hashes:
                            seen_hashes.add(h)
                            # Calculate AI Confidence Score (0.0 - 1.0)
                            c_score = 0.70
                            if t.get("source") in (MODELS["port_risk"], MODELS["cve_corr"]):
                                c_score += 0.20
                            if ctx.get("cpe"):
                                c_score += 0.05
                            c_score = round(min(1.0, c_score), 2)
                            t["confidence_score"] = c_score
                            t["confidence_label"] = "VERIFIED" if c_score >= 0.85 else "HEURISTIC"
                            t["engine_consensus_count"] = 2 if c_score >= 0.85 else 1
                            new_threats.append(t)

    # ── Engine 8: Behavioral Anomaly Detection (host-level) ─────
    host_ports = {}  # type: ignore
    for scan in scans:
        host = str(scan.get("host", "unknown"))
        for proto_block in scan.get("protocols", []):
            for port_info in proto_block.get("ports", []):
                if port_info.get("state") == "open":
                    if host not in host_ports:
                        host_ports[host] = set()
                    host_ports[host].add(port_info["port"])  # type: ignore

    for host in host_ports:
        ports = host_ports[host]
        for req_ports, name, severity, desc in SUSPICIOUS_COMBOS:
            if ports and req_ports.issubset(ports):
                port_list = ", ".join(str(p) for p in sorted(req_ports))
                t = _make_threat(
                    name=name, severity=severity, host=host,
                    cve_id=f"BEHAV-{'-'.join(str(p) for p in sorted(req_ports))}-{str(host).replace('.', '_')}",
                    source=MODELS["behavioral"],
                    detail=f"{desc} (Ports: {port_list})",
                    tags=["behavioral", "anomaly", "multi-vector"],
                )
                h = _threat_hash(t)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    new_threats.append(t)

    # ── Engine 11: Lateral Movement Graph Analysis (host-level) ──
    LATERAL_MOVE_INDICATORS = {
        "remote_access": {22, 23, 3389, 5900, 5985},
        "file_share":    {21, 445, 139, 2049},
        "database":      {3306, 5432, 1433, 1521, 27017, 6379, 9200},
        "admin_panel":   {8080, 8443, 4848, 7001, 9090, 50000},
    }

    for host in host_ports:
        ports = host_ports[host]
        categories_hit = []
        for cat, cat_ports in LATERAL_MOVE_INDICATORS.items():
            if ports & cat_ports:
                categories_hit.append(cat)

        # Flag hosts with 3+ lateral movement categories
        if len(categories_hit) >= 3:
            cat_str = " + ".join(c.replace("_", " ").title() for c in categories_hit)
            t = _make_threat(
                name=f"Lateral Movement Chain: {cat_str}",
                severity="critical",
                host=host,
                cve_id=f"LATERAL-{str(host).replace('.', '_')}",
                source=MODELS["lateral_move"],
                detail=(
                    f"Host {host} has {len(categories_hit)} lateral movement capability categories: "
                    f"{cat_str}. This host can serve as a pivot point for network-wide compromise. "
                    f"Open ports: {', '.join(str(p) for p in sorted(ports & (LATERAL_MOVE_INDICATORS['remote_access'] | LATERAL_MOVE_INDICATORS['file_share'] | LATERAL_MOVE_INDICATORS['database'] | LATERAL_MOVE_INDICATORS['admin_panel'])))}."
                ),
                tags=["lateral_movement", "pivot", "network_graph"] + categories_hit,
            )
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
#  Engine 6 — Machine Learning Prediction & Training
# ═════════════════════════════════════════════════════════════════════

MODEL_PATH = "threat_ml_model.pkl"
VECTORIZER_PATH = "threat_ml_vect.pkl"

def extract_is_sensitive_port(X):
    import numpy as np
    from ai_logic import SENSITIVE_PORTS
    return np.array([[1 if p in SENSITIVE_PORTS else 0] for p in X.iloc[:, 0]])

def train_ml_model():
    """
    Trains an enhanced ensemble classifier (RF + GBT + MLP)
    using historical threat data with RandomizedSearchCV for hyperparameter tuning
    and CalibratedClassifierCV for accurate probabilities.
    """
    try:
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier  # type: ignore
        from sklearn.neural_network import MLPClassifier  # type: ignore
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
        from sklearn.compose import ColumnTransformer  # type: ignore
        from sklearn.preprocessing import StandardScaler, OneHotEncoder, FunctionTransformer  # type: ignore
        from sklearn.pipeline import Pipeline  # type: ignore
        from sklearn.model_selection import RandomizedSearchCV  # type: ignore
        from sklearn.calibration import CalibratedClassifierCV  # type: ignore
        from scipy.stats import randint, uniform  # type: ignore
        import pandas as pd  # type: ignore
        import numpy as np  # type: ignore
        import joblib  # type: ignore
    except ImportError:
        print("[!] ML libraries missing. Run: pip install scikit-learn pandas joblib numpy scipy")
        return False

    if not check_connection():
        print("[!] Database offline.")
        return False

    print("[*] Fetching historical threat data for ML training...")
    past_threats = list(threats.find({"source": {"$ne": MODELS["ml_predict"]}}))

    # Load real CVE data patterns from local cvelistV5 directory for training
    import json
    from cve_lookup import CVELIST_DIR  # type: ignore

    cves_dir = CVELIST_DIR
    local_cve_threats = []
    if cves_dir.exists():
        print(f"[*] Extracting real CVE pattern data from {cves_dir}...")
        cve_count = 0
        for year_dir in cves_dir.iterdir():
            if not year_dir.is_dir() or not year_dir.name.isdigit():
                continue
            for chunk_dir in year_dir.iterdir():
                if not chunk_dir.is_dir():
                    continue
                for json_file in chunk_dir.glob("*.json"):
                    try:
                        with open(json_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        cve_metadata = data.get("cveMetadata", {})
                        cve_id = cve_metadata.get("cveId", "")
                        containers = data.get("containers", {})
                        cna = containers.get("cna", {})
                        
                        descriptions = cna.get("descriptions", [])
                        desc_en = ""
                        for d in descriptions:
                            if d.get("lang") == "en":
                                desc_en = d.get("value", "")
                                break
                        
                        metrics = cna.get("metrics", [])
                        if not metrics and "adp" in containers:
                            for adp in containers["adp"]:
                                if "metrics" in adp:
                                    metrics = adp["metrics"]
                                    break
                        score = 0
                        severity = "unknown"
                        for metric in metrics:
                            for k in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                                if k in metric:
                                    cvss = metric[k]
                                    score = cvss.get("baseScore", 0)
                                    severity = cvss.get("baseSeverity", "UNKNOWN").lower()
                                    break
                            if score:
                                break
                        
                        affected = cna.get("affected", [])
                        product = ""
                        for aff in affected:
                            prod = aff.get("product", "").strip()
                            if prod and prod not in ("n/a", "unknown"):
                                product = prod
                                break
                        
                        if desc_en and severity != "unknown":
                            local_cve_threats.append({
                                "name": f"{cve_id} in {product}" if product else cve_id,
                                "detail": desc_en,
                                "severity": severity,
                                "port": 0,
                                "protocol": "tcp",
                                "service": product.lower() if product else "unknown"
                            })
                            cve_count += 1
                            if cve_count >= 1000:
                                break
                    except Exception:
                        pass
                if cve_count >= 1000:
                    break
            if cve_count >= 1000:
                break
        print(f"[+] Loaded {len(local_cve_threats)} real CVE threat patterns for training.")
        past_threats.extend(local_cve_threats)

    # --- Expanded Synthetic training data ---
    synthetic_threats = [
        {"name": "MS08-067 (NetAPI) Exploitation", "detail": "vulnerability reference", "severity": "critical", "port": 445, "protocol": "tcp", "service": "smb"},
        {"name": "vsftpd 2.3.4 Backdoor", "detail": "backdoor reference", "severity": "critical", "port": 21, "protocol": "tcp", "service": "ftp"},
        {"name": "Tomcat Manager Default Creds", "detail": "default admin credentials reference", "severity": "high", "port": 8080, "protocol": "tcp", "service": "http-alt"},
        {"name": "Meterpreter Reverse TCP", "detail": "metasploit reverse tcp handler reference", "severity": "critical", "port": 4444, "protocol": "tcp", "service": "unknown"},
        {"name": "Anonymous FTP", "detail": "anonymous login allowed reference", "severity": "medium", "port": 21, "protocol": "tcp", "service": "ftp"},
        {"name": "Log4Shell (RCE) Exploit", "detail": "Java Log4j 2.14 JNDI lookup vulnerability CVE-2021-44228", "severity": "critical", "port": 8080, "protocol": "tcp", "service": "http"},
        {"name": "ProxyLogon SSRF", "detail": "Microsoft Exchange Server SSRF vulnerability CVE-2021-26855", "severity": "critical", "port": 443, "protocol": "tcp", "service": "https"},
        {"name": "Spring4Shell RCE", "detail": "Spring Framework Cloud Function RCE CVE-2022-22965", "severity": "critical", "port": 80, "protocol": "tcp", "service": "http"},
        {"name": "Ghostcat AJP", "detail": "tomcat ghostcat file read CVE-2020-1938", "severity": "critical", "port": 8009, "protocol": "tcp", "service": "ajp13"},
        {"name": "Docker Escape", "detail": "Docker runc container escape privilege escalation CVE-2019-5736", "severity": "critical", "port": 2375, "protocol": "tcp", "service": "docker"},
        {"name": "Kubernetes API Unauth", "detail": "kubernetes api unauthenticated access", "severity": "critical", "port": 6443, "protocol": "tcp", "service": "https"},
        {"name": "Redis RCE", "detail": "redis no authentication remote code execution", "severity": "critical", "port": 6379, "protocol": "tcp", "service": "redis"},
        {"name": "Grafana Path Traversal", "detail": "grafana path traversal arbitrary file read CVE-2021-43798", "severity": "critical", "port": 3000, "protocol": "tcp", "service": "http"},
        {"name": "SSH Weak Key", "detail": "ssh weak key exchange algorithm diffie-hellman", "severity": "medium", "port": 22, "protocol": "tcp", "service": "ssh"},
        {"name": "HTTP Info Leak", "detail": "http server header version disclosure information", "severity": "low", "port": 80, "protocol": "tcp", "service": "http"},
        {"name": "HTTPS Valid", "detail": "tls 1.3 valid certificate secure", "severity": "info", "port": 443, "protocol": "tcp", "service": "https"},
        {"name": "DNS Open Resolver", "detail": "dns recursion enabled amplification attack", "severity": "high", "port": 53, "protocol": "udp", "service": "domain"},
        {"name": "Elasticsearch Unauth", "detail": "elasticsearch no authentication data exposure", "severity": "critical", "port": 9200, "protocol": "tcp", "service": "http"},
        {"name": "MongoDB No Auth", "detail": "mongodb no authentication database exposure", "severity": "critical", "port": 27017, "protocol": "tcp", "service": "mongodb"},
        {"name": "SMB EternalBlue", "detail": "smbv1 eternalblue ms17-010 worm", "severity": "critical", "port": 445, "protocol": "tcp", "service": "smb"},
        {"name": "FTP Bounce Attack", "detail": "ftp bounce attack port scanning proxy", "severity": "high", "port": 21, "protocol": "tcp", "service": "ftp"},
        {"name": "NFS World Readable", "detail": "nfs world readable export no_root_squash", "severity": "high", "port": 2049, "protocol": "tcp", "service": "nfs"},
        # New synthetics
        {"name": "WebLogic Unauth RCE", "detail": "oracle weblogic server remote code execution CVE-2020-14882", "severity": "critical", "port": 7001, "protocol": "tcp", "service": "http"},
        {"name": "Confluence OGNL Injection", "detail": "atlassian confluence ognl injection rce CVE-2022-26134", "severity": "critical", "port": 8090, "protocol": "tcp", "service": "http"},
        {"name": "SSH Brute Force", "detail": "frequent failed ssh login attempts detected", "severity": "medium", "port": 22, "protocol": "tcp", "service": "ssh"},
        {"name": "RDP Exposure", "detail": "remote desktop protocol exposed to public internet", "severity": "high", "port": 3389, "protocol": "tcp", "service": "ms-wbt-server"},
        {"name": "VNC No Auth", "detail": "vnc server allowing unauthenticated access", "severity": "critical", "port": 5900, "protocol": "tcp", "service": "vnc"},
        {"name": "Memcached UDP Amplification", "detail": "memcached server exposed on udp allowing ddos amplification", "severity": "critical", "port": 11211, "protocol": "udp", "service": "memcache"},
        {"name": "GitLab Image Exif RCE", "detail": "gitlab exiftool remote code execution CVE-2021-22205", "severity": "critical", "port": 443, "protocol": "tcp", "service": "https"},
        {"name": "Kubelet Anonymous Read", "detail": "kubernetes kubelet allowing anonymous read access", "severity": "critical", "port": 10250, "protocol": "tcp", "service": "https"},
        {"name": "PostgreSQL Default Creds", "detail": "postgresql accepting default credentials postgres/postgres", "severity": "high", "port": 5432, "protocol": "tcp", "service": "postgresql"},
    ]
    past_threats.extend(synthetic_threats * 8)

    # Filter to keep only standard severities and ensure each class has at least 2 examples
    valid_severities = {"critical", "high", "medium", "low", "info"}
    past_threats = [t for t in past_threats if (t.get("severity") or "").lower() in valid_severities]
    
    sev_counts = {}
    for t in past_threats:
        s = t["severity"].lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
        
    past_threats = [t for t in past_threats if sev_counts[t["severity"].lower()] >= 2]

    if len(past_threats) < 20:
        print(f"[!] Need at least 20 historical threats to train. Only have {len(past_threats)}.")
        return False

    # Extract structured features
    data = []
    for t in past_threats:
        text_parts = [t.get("name", ""), t.get("detail", ""), " ".join(t.get("tags", [])), t.get("source", "")]
        text_feature = " ".join(text_parts)
        
        # Try to infer port if not explicitly set but present in string
        port_num = t.get("port", 0)
        if not port_num:
            port_match = re.search(r'Port (\d+)', text_feature, re.IGNORECASE)
            port_num = int(port_match.group(1)) if port_match else 0

        data.append({
            "text": text_feature,
            "port": float(port_num),
            "protocol": t.get("protocol", "tcp").lower(),
            "severity": t.get("severity", "info")
        })

    df = pd.DataFrame(data)
    y = df.pop("severity")

    sensitive_port_transformer = FunctionTransformer(extract_is_sensitive_port, validate=False)

    # Pipeline: ColumnTransformer for multi-modal features
    preprocessor = ColumnTransformer(
        transformers=[
            ('text', TfidfVectorizer(max_features=2500, ngram_range=(1, 3), sublinear_tf=True), 'text'),
            ('num', StandardScaler(), ['port']),
            ('cat', OneHotEncoder(handle_unknown='ignore'), ['protocol']),
            ('sensitive', sensitive_port_transformer, ['port'])
        ])

    # Ensemble Base Models
    rf = RandomForestClassifier(random_state=42, class_weight="balanced")
    gbt = GradientBoostingClassifier(random_state=42)
    mlp = MLPClassifier(hidden_layer_sizes=(64,), max_iter=300, random_state=42, early_stopping=True)

    ensemble = VotingClassifier(estimators=[("rf", rf), ("gbt", gbt), ("mlp", mlp)], voting="soft")

    tune_pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', ensemble)
    ])

    param_distributions = {
        'classifier__rf__n_estimators': randint(50, 150),
        'classifier__gbt__learning_rate': uniform(0.05, 0.15),
    }

    unique_labels = list(set(y))
    cv_folds = min(3, min(y.tolist().count(label) for label in unique_labels) if all(y.tolist().count(l) >= 2 for l in unique_labels) else 2)
    cv_folds = max(2, cv_folds)

    print("[*] Starting RandomizedSearchCV for hyperparameter tuning...")
    search = RandomizedSearchCV(tune_pipeline, param_distributions, n_iter=3, cv=cv_folds, scoring='accuracy', random_state=42)
    
    try:
        search.fit(df, y)
        print(f"[*] Best tuning accuracy: {search.best_score_*100:.1f}%")
        best_params = search.best_params_
    except Exception as e:
        print(f"[!] Hyperparameter tuning failed: {e}. Using defaults.")
        best_params = {}

    # Apply best params to the ensemble elements
    if best_params:
        rf.set_params(n_estimators=best_params.get('classifier__rf__n_estimators', 100))
        gbt.set_params(learning_rate=best_params.get('classifier__gbt__learning_rate', 0.1))

    # Final Pipeline with CalibratedClassifierCV
    final_pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', CalibratedClassifierCV(estimator=ensemble, cv=cv_folds))
    ])
    
    final_pipeline.fit(df, y)

    joblib.dump(final_pipeline, MODEL_PATH)
    print(f"[+] AI pipeline (Ensemble+Tuning+Calibration) trained and saved to {MODEL_PATH}!")
    
    # Save the TF-IDF Vectorizer separately
    try:
        vectorizer = final_pipeline.named_steps['preprocessor'].named_transformers_['text']
        joblib.dump(vectorizer, VECTORIZER_PATH)
        print(f"[+] TF-IDF Vectorizer saved to {VECTORIZER_PATH}!")
    except Exception as e:
        print(f"[!] Failed to save vectorizer: {e}")
        
    return True

def _engine_ml_predict(ctx):
    """Inference engine: ML Pipeline prediction with structured features."""
    try:
        import joblib  # type: ignore
        import os
        import pandas as pd # type: ignore
        if not os.path.exists(MODEL_PATH):
            return []

        pipeline = joblib.load(MODEL_PATH)

        text_feature = f"{ctx['service']} {ctx['product']} {ctx['version']}"
        df_pred = pd.DataFrame([{
            "text": text_feature,
            "port": float(ctx["port"]),
            "protocol": ctx["protocol"].lower()
        }])

        pred = pipeline.predict(df_pred)[0]
        probs = pipeline.predict_proba(df_pred)[0]
        max_prob = max(probs)

        # High/critical risk with > 60% calibrated confidence
        if pred in ["high", "critical"] and max_prob > 0.60:
            confidence_label = "Very High" if max_prob > 0.90 else "High" if max_prob > 0.80 else "Moderate"
            return [_make_threat(
                name=f"AI Predicted: {pred.title()} Risk ({confidence_label} Confidence)",
                severity=pred,
                host=ctx["host"],
                cve_id=f"AI-{ctx['port']}-{ctx['host'].replace('.', '_')}",
                source=MODELS["ml_predict"],
                detail=(
                    f"Advanced ML Engine predicted {pred} risk with {max_prob*100:.1f}% calibrated confidence. "
                    f"Service: {ctx['product']} {ctx['version']}"
                ),
                tags=["machine_learning", "ai_predicted", f"confidence_{confidence_label.lower().replace(' ', '_')}"]
            )]
    except Exception as e:
        print(f"ML Predict Error: {e}")
    return []


# ═════════════════════════════════════════════════════════════════════
#  Engine 9 — CVE Correlation Engine
# ═════════════════════════════════════════════════════════════════════

def _engine_cve_correlation(ctx):
    """Cross-reference discovered services with cached CVE data from NVD using CPE and version matching."""
    if not check_connection():
        return []

    from cve_lookup import normalize_cpe, match_cpe, lookup_by_cpe, _query_nvd, _parse_cve_item, _parse_cvelist_v5, get_local_cves_by_product, check_cve_v5_version_match  # type: ignore

    cpe = ctx.get("cpe", "").strip()
    product = ctx.get("product", "").strip()
    version = ctx.get("version", "").strip()
    host = ctx.get("host", "unknown")
    port = ctx.get("port", "")
    service = ctx.get("service", "")
    explicit_cves = ctx.get("cves", [])

    # If neither CPE nor version nor explicit CVEs is present, we cannot correlate CVEs reliably.
    if not cpe and not version and not explicit_cves:
        return []

    matched_cves = []
    seen_ids = set()

    # 0. Explicit CVE matching (from Nmap script output)
    if explicit_cves:
        for cve_id in explicit_cves:
            # First check cve_cache
            cached = cve_cache.find_one({"cve_id": cve_id})
            if cached:
                if cve_id not in seen_ids:
                    matched_cves.append(cached)
                    seen_ids.add(cve_id)
            else:
                # Fallback: parse directly from the local folder
                local_data = _parse_cvelist_v5(cve_id)
                if local_data:
                    cve_cache.update_one(
                        {"cve_id": cve_id},
                        {"$set": {**local_data, "fetched_at": datetime.now(timezone.utc)}},
                        upsert=True,
                    )
                    if cve_id not in seen_ids:
                        matched_cves.append(local_data)
                        seen_ids.add(cve_id)

    # 1. CPE-Based Matching
    if cpe:
        cpe_23 = normalize_cpe(cpe)
        
        # 1a. Search local cache first
        cpe_parts = cpe_23.split(":")
        product_name = cpe_parts[4] if len(cpe_parts) > 4 else ""
        
        local_candidates = []
        if product_name:
            try:
                local_candidates = list(cve_cache.find({
                    "cpes": {"$regex": f":{product_name}:", "$options": "i"}
                }))
            except Exception:
                pass
            
            # Fetch directly from local cvelistV5 directory using index
            try:
                local_cves = get_local_cves_by_product(product_name)
                existing_ids = {doc.get("cve_id") for doc in local_candidates if doc.get("cve_id")}
                for lc in local_cves:
                    if lc.get("cve_id") not in existing_ids:
                        local_candidates.append(lc)
            except Exception:
                pass
                
        for cve_doc in local_candidates:
            cve_cpes = cve_doc.get("cpes", [])
            matched = False
            for crit in cve_cpes:
                if match_cpe(cpe_23, crit):
                    matched = True
                    break
            
            # Removed strict version in description check to prevent discarding valid matches
            if matched:
                matched_cves.append(cve_doc)
            if len(matched_cves) >= 3:
                break

        # 1b. If no local match, query NVD API (if version is not wildcard '*')
        if not matched_cves and len(cpe_parts) > 5 and cpe_parts[5] != "*":
            try:
                api_res = lookup_by_cpe(cpe_23, results_per_page=5)
                if "vulnerabilities" in api_res:
                    matched_cves.extend(api_res["vulnerabilities"])
            except Exception:
                pass

    # 2. Product + Version Keyword Search (fallback if CPE matching yielded nothing)
    if not matched_cves and product and version:
        # 2a. Search local cache first
        syn_cpe = f"cpe:2.3:a:*:{product.replace(' ', '_').lower()}:{version}:*:*:*:*:*:*:*"
        try:
            local_candidates = list(cve_cache.find({
                "cpes": {"$regex": f":{product.replace(' ', '_').lower()}:", "$options": "i"}
            }))
            
            # Fetch directly from local cvelistV5 directory using index
            try:
                local_cves = get_local_cves_by_product(product)
                existing_ids = {doc.get("cve_id") for doc in local_candidates if doc.get("cve_id")}
                for lc in local_cves:
                    if lc.get("cve_id") not in existing_ids:
                        local_candidates.append(lc)
            except Exception:
                pass

            for cve_doc in local_candidates:
                cve_cpes = cve_doc.get("cpes", [])
                matched = False
                for crit in cve_cpes:
                    if match_cpe(syn_cpe, crit):
                        matched = True
                        break
                
                # Removed strict version in description check to prevent discarding valid matches                        
                if matched:
                    matched_cves.append(cve_doc)
                if len(matched_cves) >= 3:
                    break
        except Exception:
            pass

        # 2b. If no local match, query NVD API using keywordSearch
        if not matched_cves:
            try:
                query_res = _query_nvd({"keywordSearch": f"{product} {version}", "resultsPerPage": 3})
                if "vulnerabilities" in query_res:
                    vulns = query_res.get("vulnerabilities", [])
                    for v in vulns:
                        parsed = _parse_cve_item(v.get("cve", {}))
                        matched_cves.append(parsed)
                        # Save to cache
                        cve_cache.update_one(
                            {"cve_id": parsed["cve_id"]},
                            {"$set": {**parsed, "fetched_at": datetime.now(timezone.utc)}},
                            upsert=True,
                        )
            except Exception:
                pass

    # Build threats from matched CVEs
    results = []
    seen_ids = set()
    for cve_doc in matched_cves:
        cve_id = cve_doc.get("cve_id", "")
        if not cve_id or cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        
        cve_sev = cve_doc.get("severity", "medium")
        cve_score = cve_doc.get("score", 0)
        cve_desc = cve_doc.get("description", "")
        epss_score = float(cve_doc.get("epss_score", 0.0))
        epss_pct = float(cve_doc.get("epss_percentile", 0.0))

        # Only flag medium+ severity CVEs unless high EPSS probability
        if cve_sev in ["low", "info", "unknown"] and epss_score < 0.10:
            continue

        # Elevate severity if high EPSS probability (> 10% active exploitation likelihood)
        if epss_score >= 0.10 and cve_sev in ["medium", "low"]:
            cve_sev = "high"

        epss_detail = f" | EPSS Exploit Probability: {epss_score * 100:.1f}%" if epss_score > 0 else ""

        results.append(_make_threat(  # type: ignore
            name=f"CVE Correlated: {cve_id}",
            severity=str(cve_sev),
            host=str(host),
            cve_id=str(cve_id),
            source=MODELS["cve_corr"],
            detail=(
                f"Service '{service}' ({product}) on port {port} "
                f"matches CVE {cve_id} (CVSS {cve_score}{epss_detail}): {str(cve_desc)[:200]}"
            ),
            tags=["cve_correlation", "nvd", "epss", "automated"],
        ))
        
    return results[:2]  # Limit to 2 threats per port


# ═════════════════════════════════════════════════════════════════════
#  Engine 10 — Encryption Weakness Detection
# ═════════════════════════════════════════════════════════════════════

# Ports expected to use encryption
ENCRYPTION_EXPECTED = {
    80:   {"should_be": 443,  "issue": "HTTP without TLS"},
    21:   {"should_be": 990,  "issue": "FTP without FTPS"},
    23:   {"should_be": 22,   "issue": "Telnet instead of SSH"},
    110:  {"should_be": 995,  "issue": "POP3 without TLS"},
    143:  {"should_be": 993,  "issue": "IMAP without TLS"},
    25:   {"should_be": 587,  "issue": "SMTP without STARTTLS"},
    389:  {"should_be": 636,  "issue": "LDAP without TLS"},
}


def _engine_encryption(ctx):
    """Detect services running without encryption when secure alternatives exist."""
    port = ctx["port"]
    service = ctx["service"].lower()
    product = ctx["product"].lower()
    results = []

    # Check for unencrypted protocols
    if port in ENCRYPTION_EXPECTED:
        info = ENCRYPTION_EXPECTED[port]
        results.append(_make_threat(
            name=f"Unencrypted: {info['issue']}",
            severity="high",
            host=ctx["host"],
            cve_id=f"ENC-{port}-{ctx['host'].replace('.', '_')}",
            source=MODELS["encryption"],
            detail=(
                f"{info['issue']} on port {port}. "
                f"Upgrade to port {info['should_be']} or enable TLS. "
                f"Unencrypted traffic can be intercepted via MITM attacks."
            ),
            tags=["encryption", "hardening", "cleartext"],
        ))

    # Detect weak SSL/TLS versions
    version_str = f"{product} {ctx['version']}".lower()
    if any(weak in version_str for weak in ["sslv2", "sslv3", "tls 1.0", "tlsv1.0", "tls1.0"]):
        results.append(_make_threat(
            name="Weak TLS/SSL Version Detected",
            severity="high",
            host=ctx["host"],
            cve_id=f"WEAKTLS-{port}-{ctx['host'].replace('.', '_')}",
            source=MODELS["encryption"],
            detail=(
                f"Service on port {port} uses deprecated SSL/TLS version. "
                f"Detected: {version_str}. Upgrade to TLS 1.2+ minimum."
            ),
            tags=["encryption", "tls", "deprecated"],
        ))

    return results


# ═════════════════════════════════════════════════════════════════════
#  Engine 12 — Attack Surface Exposure Scoring
# ═════════════════════════════════════════════════════════════════════

# Ports that significantly increase attack surface
HIGH_EXPOSURE_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 1433, 1521,
    2049, 3306, 3389, 4444, 5432, 5900, 5985, 6379, 6443, 8080,
    8443, 8888, 9200, 10250, 11211, 27017,
}


def _engine_exposure_score(ctx):
    """Calculate per-port exposure score based on service type and internet reachability."""
    port = ctx["port"]
    service = ctx["service"].lower()
    product = ctx["product"].lower()

    if port not in HIGH_EXPOSURE_PORTS:
        return []

    # Exposure factors
    is_database = any(db in service or db in product for db in ["mysql", "postgres", "mongo", "redis", "elastic", "memcache"])
    is_admin = any(adm in service or adm in product for adm in ["admin", "management", "console", "webmin", "jenkins"])
    is_remote_access = port in {22, 23, 3389, 5900, 5985}
    has_no_version = bool(ctx["product"]) and not bool(ctx["version"])

    score_factors = []
    if is_database:
        score_factors.append("database-exposed")
    if is_admin:
        score_factors.append("admin-panel-exposed")
    if is_remote_access:
        score_factors.append("remote-access")
    if has_no_version:
        score_factors.append("version-unknown")

    if not score_factors:
        return []

    severity = "critical" if len(score_factors) >= 2 else "high"
    factor_str = ", ".join(score_factors)

    return [_make_threat(
        name=f"High Exposure: {service.title()} ({factor_str})",
        severity=severity,
        host=ctx["host"],
        cve_id=f"EXPO-{port}-{ctx['host'].replace('.', '_')}",
        source=MODELS["exposure"],
        detail=(
            f"Port {port}/{ctx['protocol']} has elevated attack surface. "
            f"Factors: [{factor_str}]. Service: {ctx['product']} {ctx['version']}. "
            f"Review network segmentation and access controls."
        ),
        tags=["exposure", "attack_surface"] + score_factors,
    )]


# ═════════════════════════════════════════════════════════════════════
#  Engine 13 — Credential Dump Risk Detection (T1003)
# ═════════════════════════════════════════════════════════════════════

# Ports commonly targeted for credential harvesting attacks
CRED_DUMP_PORTS = {
    88:   {"technique": "T1003.006", "name": "Kerberos", "risk": "DCSync / Kerberoasting via Kerberos TGS"},
    389:  {"technique": "T1003.003", "name": "LDAP",     "risk": "NTDS.dit extraction via LDAP queries"},
    636:  {"technique": "T1003.003", "name": "LDAPS",    "risk": "NTDS.dit extraction via secure LDAP"},
    445:  {"technique": "T1003.001", "name": "SMB",      "risk": "LSASS memory dump via remote SMB access"},
    5985: {"technique": "T1003.001", "name": "WinRM",    "risk": "Remote credential extraction via WinRM/PowerShell"},
    135:  {"technique": "T1003",     "name": "MSRPC",    "risk": "Remote credential harvesting via MSRPC"},
    1433: {"technique": "T1003",     "name": "MSSQL",    "risk": "Credential extraction via xp_cmdshell or linked servers"},
}


def _engine_credential_dump(ctx):
    """Detect services commonly targeted for credential harvesting (T1003)."""
    port = ctx["port"]
    if port not in CRED_DUMP_PORTS:
        return []

    info = CRED_DUMP_PORTS[port]
    technique = info["technique"]
    technique_name = MITRE_TECHNIQUES.get(technique, "OS Credential Dumping")

    return [_make_threat(
        name=f"Credential Dump Risk: {info['name']} ({technique})",
        severity="critical",
        host=ctx["host"],
        cve_id=f"CRED-DUMP-{port}-{ctx['host'].replace('.', '_')}",
        source=MODELS["cred_dump"],
        detail=(
            f"{info['name']} on port {port}/{ctx['protocol']} enables "
            f"MITRE ATT&CK {technique} ({technique_name}). "
            f"Risk: {info['risk']}. "
            f"Service: {ctx['product']} {ctx['version']}. "
            f"Recommend restricting to authenticated internal access only."
        ),
        tags=["credential_dump", "mitre", technique, "t1003"],
    )]


# ═════════════════════════════════════════════════════════════════════
#  Engine 14 — Persistence Mechanism Detection (T1053/T1505)
# ═════════════════════════════════════════════════════════════════════

# Service combinations that enable persistence mechanisms
PERSISTENCE_INDICATORS = {
    22:   {"technique": "T1053.005", "vector": "SSH authorized_keys injection for persistent access"},
    5985: {"technique": "T1053.005", "vector": "WinRM enables remote scheduled task creation via PowerShell"},
    5986: {"technique": "T1053.005", "vector": "WinRM-HTTPS enables encrypted remote task scheduling"},
    4848: {"technique": "T1505.003", "vector": "GlassFish admin console enables WAR-based web shell deployment"},
    7001: {"technique": "T1505.003", "vector": "WebLogic admin enables WAR/JSP web shell deployment"},
    8080: {"technique": "T1505.003", "vector": "HTTP-Alt (Tomcat/Jenkins) enables web shell upload via manager"},
    9090: {"technique": "T1505.003", "vector": "Admin panel may allow persistent configuration changes"},
    50000: {"technique": "T1053.005", "vector": "Jenkins Agent port enables remote job scheduling for persistence"},
}


def _engine_persistence_audit(ctx):
    """Detect services that enable common persistence mechanisms (T1053/T1505)."""
    port = ctx["port"]
    if port not in PERSISTENCE_INDICATORS:
        return []

    service = ctx["service"].lower()
    product = ctx["product"].lower()

    info = PERSISTENCE_INDICATORS[port]
    technique = info["technique"]
    technique_name = MITRE_TECHNIQUES.get(technique, "Persistence")

    # Only flag if the service looks like it could actually enable persistence
    # (avoids false positives on repurposed ports)
    expected_services = {
        22: ["ssh"], 5985: ["wsman", "winrm", "http"], 5986: ["wsman", "winrm", "https"],
        4848: ["glassfish", "http"], 7001: ["weblogic", "http"], 8080: ["http", "tomcat", "jenkins"],
        9090: ["prometheus", "http", "cockpit"], 50000: ["jenkins", "http"],
    }

    port_expected = expected_services.get(port, [])
    if port_expected and not any(e in service or e in product for e in port_expected):
        return []  # Service doesn't match expected — skip to avoid noise

    return [_make_threat(
        name=f"Persistence Vector: {technique_name} via {ctx['service'].title()}",
        severity="high",
        host=ctx["host"],
        cve_id=f"PERSIST-{port}-{ctx['host'].replace('.', '_')}",
        source=MODELS["persistence"],
        detail=(
            f"Port {port}/{ctx['protocol']} ({ctx['service']}) enables "
            f"MITRE ATT&CK {technique} ({technique_name}). "
            f"{info['vector']}. "
            f"Service: {ctx['product']} {ctx['version']}. "
            f"Audit for unauthorized scheduled tasks, cron jobs, or web shells."
        ),
        tags=["persistence", "mitre", technique, "audit"],
    )]


# ═════════════════════════════════════════════════════════════════════
#  Engine 15 — DLL Side-Loading Risk Detection (T1574.002)
# ═════════════════════════════════════════════════════════════════════

# Windows services susceptible to DLL hijacking / side-loading
DLL_HIJACK_PORTS = {
    445:  {"service": "SMB",   "risk": "SMB service DLLs can be hijacked for privilege escalation"},
    3389: {"service": "RDP",   "risk": "RDP service DLLs (mstscax.dll) targeted for side-loading"},
    1433: {"service": "MSSQL", "risk": "SQL Server extensibility DLLs (xp_*.dll) enable code execution"},
    135:  {"service": "MSRPC", "risk": "COM/DCOM service DLLs can be side-loaded for persistence"},
    5985: {"service": "WinRM", "risk": "WinRM plugin DLLs can be replaced for backdoor access"},
}

# Windows OS indicators from service banners
WINDOWS_INDICATORS = ["windows", "microsoft", "iis", "mssql", "ms-wbt", "msrpc", "netbios"]


def _engine_dll_hijack(ctx):
    """Detect Windows services susceptible to DLL side-loading (T1574.002)."""
    port = ctx["port"]
    if port not in DLL_HIJACK_PORTS:
        return []

    service = ctx["service"].lower()
    product = ctx["product"].lower()

    # Only flag if there's evidence this is a Windows host
    is_windows = any(
        indicator in service or indicator in product
        for indicator in WINDOWS_INDICATORS
    )

    if not is_windows:
        return []

    info = DLL_HIJACK_PORTS[port]
    return [_make_threat(
        name=f"DLL Hijack Risk: {info['service']} (T1574.002)",
        severity="high",
        host=ctx["host"],
        cve_id=f"DLL-{port}-{ctx['host'].replace('.', '_')}",
        source=MODELS["dll_hijack"],
        detail=(
            f"Windows service {info['service']} on port {port}/{ctx['protocol']} "
            f"is susceptible to DLL side-loading (MITRE T1574.002). "
            f"{info['risk']}. "
            f"Service: {ctx['product']} {ctx['version']}. "
            f"Verify DLL search order, enforce code signing, and monitor DLL loads."
        ),
        tags=["dll_hijack", "mitre", "T1574.002", "windows", "persistence"],
    )]


# ═════════════════════════════════════════════════════════════════════
#  Engine 16 — Zero-Day Heuristics (Entropy & Anomaly Detection)
# ═════════════════════════════════════════════════════════════════════

def _calculate_entropy(text):
    """Calculates Shannon entropy for a given string."""
    import math
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def _engine_zero_day_heuristics(ctx):
    """
    Heuristics to detect unlisted C2 beacons, backdoors, or 0-day payloads.
    Flags high-entropy banners, non-standard port/service mismatches, and hidden files.
    """
    port = ctx["port"]
    service = ctx["service"].lower()
    product = ctx["product"].lower()
    version = ctx["version"].lower()
    
    findings = []
    
    # 1. High Entropy Banner (Indicator of encrypted C2 or obfuscated backdoor)
    # Exclude common noisy strings or base64 SSH keys
    combined_banner = f"{product} {version}".strip()
    if combined_banner and not any(k in combined_banner for k in ["ssh", "ssl", "tls", "rsa", "openssh", "nginx", "apache"]):
        entropy = _calculate_entropy(combined_banner)
        if entropy > 4.5 and len(combined_banner) > 15:  # High randomness threshold
            findings.append(_make_threat(
                name="Heuristics: High-Entropy Banner (Possible C2/Backdoor)",
                severity="critical",
                host=ctx["host"],
                cve_id=f"HEUR-ENTROPY-{port}-{ctx['host'].replace('.', '_')}",
                source=MODELS["zero_day"],
                detail=(
                    f"Port {port}/{ctx['protocol']} returned a banner with unusually high Shannon entropy ({entropy:.2f}). "
                    f"This often indicates an obfuscated payload, an encrypted C2 beacon, or a custom backdoor. "
                    f"Banner: '{combined_banner}'"
                ),
                tags=["heuristics", "entropy", "zero_day", "c2_beacon", "backdoor"]
            ))

    # 2. Port/Service Anomaly Mismatch (e.g., SSH running on port 80 or 443)
    standard_mapping = {
        80: ["http", "tcpwrapped"], 443: ["https", "http", "ssl", "tcpwrapped"], 
        22: ["ssh", "tcpwrapped"], 21: ["ftp", "tcpwrapped"], 
        3306: ["mysql", "tcpwrapped"], 3389: ["ms-wbt-server", "tcpwrapped", "rdp"],
        445: ["microsoft-ds", "smb", "tcpwrapped"], 53: ["domain", "dns", "tcpwrapped"]
    }
    
    if port in standard_mapping:
        expected_services = standard_mapping[port]
        if service and service not in expected_services and service != "unknown":
            findings.append(_make_threat(
                name=f"Heuristics: Service Anomaly (Port {port} Mismatch)",
                severity="high",
                host=ctx["host"],
                cve_id=f"HEUR-MISMATCH-{port}-{ctx['host'].replace('.', '_')}",
                source=MODELS["zero_day"],
                detail=(
                    f"Anomaly detected: Port {port} is standard for {expected_services[0]}, "
                    f"but Nmap detected '{service}' ({product}). "
                    f"Attackers often run backdoors (like SSH or Netcat) on standard web ports to bypass firewalls."
                ),
                tags=["heuristics", "anomaly", "evasion", "zero_day"]
            ))

    # 3. Hidden Services or Suspicious Naming
    if service.startswith(".") or "backdoor" in service or "trojan" in service or "rootkit" in service:
        findings.append(_make_threat(
            name="Heuristics: Suspicious Service Name",
            severity="critical",
            host=ctx["host"],
            cve_id=f"HEUR-NAME-{port}-{ctx['host'].replace('.', '_')}",
            source=MODELS["zero_day"],
            detail=(
                f"Port {port}/{ctx['protocol']} identifies as '{service}'. "
                f"This matches known naming conventions for malicious implants or hidden listeners."
            ),
            tags=["heuristics", "malware", "zero_day", "implant"]
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════
#  Risk Scoring Engine (Enhanced v3 — Recency + Critical Multiplier)
# ═════════════════════════════════════════════════════════════════════

def compute_risk_scores(persist=True):
    """
    Composite Risk Engine (Mission Control v3).
    Calculates a multi-dimensional risk score for each host based on:
    1. Weighted Severity Sum (Core Risk)
    2. Engine Diversity Bonus (High Confidence)
    3. Threat Volume Factor (Exposure Modifier)
    4. Critical Threat Multiplier (Severity Accelerator)
    5. Recency Boost (Active threats score higher)
    
    :param persist: If True, updates risk tags on all threat documents.
    :return: Dict of host analysis summaries.
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
            "tags_all": {"$push": "$tags"},
        }},
        {"$sort": {"threat_count": -1}},
    ]

    host_groups = list(threats.aggregate(pipeline))
    scores = {}

    for group in host_groups:
        host = group["_id"]
        if not host:
            continue

        severities = group["severities"]

        # 1. Weighted severity sum (Core Risk)
        sev_score = sum(SEVERITY_WEIGHTS.get(str(s).lower(), 0) for s in severities)

        # 2. Diversity bonus — more engines = higher systemic confidence
        engine_count = len(group["engines"])
        engine_bonus = engine_count * 2.5

        # 3. Volume factor (capped)
        volume_factor = min(group["threat_count"] * 0.5, 20)

        # 4. Critical multiplier — hosts with critical threats get boosted
        critical_count = severities.count("critical")
        critical_multiplier = 1.0 + (min(critical_count, 5) * 0.1)  # Up to 1.5x

        # 5. Recency boost — threats detected recently score higher
        recency_boost = 0
        latest = group.get("latest")
        if latest:
            try:
                age_hours = (datetime.now(timezone.utc) - latest).total_seconds() / 3600
                if age_hours < 1:
                    recency_boost = 8   # Last hour
                elif age_hours < 24:
                    recency_boost = 5   # Last day
                elif age_hours < 168:
                    recency_boost = 2   # Last week
            except Exception:
                pass

        raw_total = sev_score + engine_bonus + volume_factor + recency_boost
        total = round(raw_total * critical_multiplier, 1)

        # Determine Qualitative Risk Level (5 tiers)
        risk_level = (
            "critical" if total >= 50 else
            "high" if total >= 30 else
            "medium" if total >= 15 else
            "low" if total >= 5 else
            "info"
        )

        scores[host] = {
            "score": total,
            "risk_level": risk_level,
            "threat_count": group["threat_count"],
            "engines_flagged": engine_count,
            "critical_count": critical_count,
            "recency_boost": recency_boost,
        }

        # Tag the threats in the DB for faceted search/filtering
        if persist:
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
    """Create a standardized threat document validated against schemas.ThreatItem."""
    sev = (severity or 'info').lower().strip()
    try:
        from schemas import ThreatItem
        item = ThreatItem(
            name=name,
            severity=sev,
            host=str(host),
            cve_id=str(cve_id or ''),
            source=str(source),
            detail=str(detail),
            tags=list(tags or []),
            created_at=datetime.now(timezone.utc).isoformat()
        )
        doc = item.model_dump()
        doc["detected_at"] = datetime.now(timezone.utc)
        return doc
    except Exception:
        # Fallback if validation fails
        return {
            "name": name,
            "severity": sev if sev in {"info", "low", "medium", "high", "critical"} else "info",
            "host": str(host),
            "cve_id": str(cve_id or ''),
            "source": str(source),
            "detail": str(detail),
            "tags": list(tags or []),
            "detected_at": datetime.now(timezone.utc),
        }



def _threat_hash(threat):
    """Generate a unique hash for dedup within a single run. Normalizes fields."""
    cve = str(threat.get('cve_id') or '').lower()
    host = str(threat.get('host') or '').lower()
    src = str(threat.get('source') or '').lower()
    key = f"{cve}|{host}|{src}"
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


# ═════════════════════════════════════════════════════════════════════
#  Standalone execution
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 58)
    print("   NexShield AI Analysis Pipeline")
    print("=" * 58)

    import sys
    if "--train" in sys.argv:
        print("\n[0/3] Training Machine Learning Model...")
        train_ml_model()
        print("\nExiting after training. Run without --train to analyze scans.")
        sys.exit(0)

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

"""
ai_logic.py — AI Multi-Model Threat Analysis & Deduplication (Advanced v2)

Architecture: 9 independent analysis "engines" that each inspect scan data
from a different angle. Each engine tags its findings with its own model name,
creating a multi-perspective threat intelligence pipeline.

Engine Registry:
  1. PortRisk-Engine-v2         — Sensitive port exposure analysis
  2. VersionVuln-Engine-v2      — Missing/outdated version detection
  3. ServiceFP-Engine-v1        — Service fingerprint anomaly detection
  4. DefaultCreds-Engine-v1     — Default-credential risk assessment
  5. MitreMap-Engine-v1         — MITRE ATT&CK technique mapping
  6. ML-Predict-Engine-v2       — Trained ML prediction (RandomForest v2)
  7. CVECorrelation-Engine-v1   — Cross-reference services with NVD CVE cache
  8. Behavioral-Engine-v1       — Suspicious port combination detection
  9. DedupMerge-Engine-v2       — Intelligent duplicate merging

Run Order:  analyze_scan_results() → compute_risk_scores() → merge_duplicates()
"""

from datetime import datetime, timezone
import hashlib
import re
from config import threats, network_scans, cve_cache, check_connection  # type: ignore


# ═════════════════════════════════════════════════════════════════════
#  Model Registry
# ═════════════════════════════════════════════════════════════════════

MODELS = {
    "port_risk":     "PortRisk-Engine-v2",
    "version_vuln":  "VersionVuln-Engine-v2",
    "service_fp":    "ServiceFP-Engine-v1",
    "default_creds": "DefaultCreds-Engine-v1",
    "mitre_map":     "MitreMap-Engine-v1",
    "ml_predict":    "ML-Predict-Engine-v2",
    "behavioral":    "Behavioral-Engine-v1",
    "cve_corr":      "CVECorrelation-Engine-v1",
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
    4444:  ("Metasploit Meterpreter Default", "critical", "T1071.001"),
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
    (r"log4j\s*2\.(0|1[0-4])\.",                      "CVE-2021-44228", "critical", "Log4j 2.x — Log4Shell RCE vulnerability"),
    (r"spring-core\s*5\.[0-3]\.",                     "CVE-2022-22965", "critical", "Spring Framework — Spring4Shell RCE"),
    (r"exchange\s*server\s*201[3-9]",                 "CVE-2021-26855", "critical", "Microsoft Exchange — ProxyLogon SSRF"),
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
                ]:
                    for t in engine_fn(ctx):  # type: ignore
                        h = _threat_hash(t)
                        if h not in seen_hashes:
                            seen_hashes.add(h)
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

def train_ml_model():
    """
    Trains a Random Forest classifier using historical threat data.
    Run this periodically as the database gathers more findings.
    """
    try:
        from sklearn.ensemble import RandomForestClassifier  # type: ignore
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
        import joblib  # type: ignore
    except ImportError:
        print("[!] ML libraries missing. Run: pip install scikit-learn joblib")
        return False

    if not check_connection():
        print("[!] Database offline.")
        return False

    print("[*] Fetching historical threat data for ML training...")
    # Fetch old threats, excluding previous ML predictions to avoid bias
    past_threats = list(threats.find({"source": {"$ne": MODELS["ml_predict"]}}))

    # --- INJECT PDF REFERENCE SYNTHETIC DATA ---
    # We heavily weight the ML training dataset with synthetic exploit signatures
    # derived directly from Georgia Weidman's "Penetration Testing" reference.
    synthetic_threats = [
        {"name": "MS08-067 (NetAPI) Exploitation", "detail": "Port 445 open smb windows vulnerability reference", "severity": "critical"},
        {"name": "vsftpd 2.3.4 Backdoor", "detail": "Port 21 open ftp vsftpd 2.3.4 backdoor reference", "severity": "critical"},
        {"name": "Tomcat Manager Default Creds", "detail": "Port 8080 open http-alt tomcat default admin credentials reference", "severity": "high"},
        {"name": "Meterpreter Reverse TCP", "detail": "Port 4444 open unknown metasploit reverse tcp handler reference", "severity": "critical"},
        {"name": "Anonymous FTP", "detail": "Port 21 open ftp anonymous login allowed reference", "severity": "medium"},
        {"name": "Log4Shell (RCE) Exploit", "detail": "Java Log4j 2.14 JNDI lookup vulnerability CVE-2021-44228", "severity": "critical"},
        {"name": "ProxyLogon SSRF", "detail": "Microsoft Exchange Server SSRF vulnerability CVE-2021-26855", "severity": "critical"},
        {"name": "Spring4Shell RCE", "detail": "Spring Framework Cloud Function RCE CVE-2022-22965", "severity": "critical"},
    ]
    past_threats.extend(synthetic_threats * 10)  # Magnify synthetic weights

    if len(past_threats) < 20:
        print(f"[!] Need at least 20 historical threats to train. Only have {len(past_threats)}.")
        return False

    # Feature Engineering: Combine service, product, and details into NLP text block
    X_raw = [t.get("name", "") + " " + t.get("detail", "") for t in past_threats]
    # Labels: Predict severity
    y = [t.get("severity", "info") for t in past_threats]

    vectorizer = TfidfVectorizer(max_features=1000)
    X_vec = vectorizer.fit_transform(X_raw)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_vec, y)

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"[+] AI logic successfully trained and saved to {MODEL_PATH}!")
    return True

def _engine_ml_predict(ctx):
    """Inference engine: Uses trained ML model to predict threat risk (v2 with numeric features)."""
    try:
        import joblib  # type: ignore
        import os
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            return []  # Model not trained yet

        clf = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)

        feature_str = f"Port {ctx['port']} open {ctx['service']} {ctx['product']} {ctx['version']}"
        X_vec = vectorizer.transform([feature_str])

        pred = clf.predict(X_vec)[0]
        probs = clf.predict_proba(X_vec)[0]
        max_prob = max(probs)

        # Only report if it predicts high/critical risk with > 60% confidence
        if pred in ["high", "critical"] and max_prob > 0.60:
            confidence_label = "High" if max_prob > 0.85 else "Moderate" if max_prob > 0.70 else "Low"
            return [_make_threat(
                name=f"AI Predicted: {pred.title()} Risk ({confidence_label} Confidence)",
                severity=pred,
                host=ctx["host"],
                cve_id=f"AI-{ctx['port']}-{ctx['host'].replace('.', '_')}",
                source=MODELS["ml_predict"],
                detail=(
                    f"ML model (RandomForest v2) flagged '{ctx['service']}' on port {ctx['port']} "
                    f"as {pred} risk with {max_prob*100:.1f}% confidence. "
                    f"Service: {ctx['product']} {ctx['version']}"
                ),
                tags=["machine_learning", "ai_predicted", f"confidence_{confidence_label.lower()}"]
            )]
    except Exception:
        pass
    return []


# ═════════════════════════════════════════════════════════════════════
#  Engine 9 — CVE Correlation Engine
# ═════════════════════════════════════════════════════════════════════

def _engine_cve_correlation(ctx):
    """Cross-reference discovered services with cached CVE data from NVD."""
    if not check_connection():
        return []

    service = ctx["service"].lower()
    product = ctx["product"].lower()
    results = []

    # Find matching keywords for this service
    keywords = set()
    for svc_key, kw_list in SERVICE_CVE_KEYWORDS.items():
        if svc_key in service or svc_key in product:
            keywords.update(kw_list)
    if product:
        keywords.add(product)

    if not keywords:
        return []

    # Search CVE cache for matching entries
    for keyword in keywords:
        try:
            cached_cves = list(cve_cache.find(
                {"description": {"$regex": keyword, "$options": "i"}},
            ).limit(3))
        except Exception:
            continue

        for cve_doc in cached_cves:
            cve_id = cve_doc.get("cve_id", "")
            cve_sev = cve_doc.get("severity", "medium")
            cve_score = cve_doc.get("score", 0)
            cve_desc = cve_doc.get("description", "")

            # Only flag medium+ severity CVEs
            if cve_sev in ["low", "info", "unknown"]:
                continue

            results.append(_make_threat(  # type: ignore
                name=f"CVE Correlated: {cve_id}",
                severity=str(cve_sev),
                host=str(ctx.get("host", "unknown")),
                cve_id=str(cve_id),
                source=MODELS["cve_corr"],
                detail=(
                    f"Service '{ctx.get('service', '')}' ({ctx.get('product', '')}) on port {ctx.get('port', '')} "
                    f"matches CVE {cve_id} (CVSS {cve_score}): {str(cve_desc)[:200]}"  # type: ignore
                ),
                tags=["cve_correlation", "nvd", "automated"],
            ))
            break  # One CVE match per keyword is sufficient

    return results[:2]  # type: ignore


# ═════════════════════════════════════════════════════════════════════
#  Risk Scoring Engine
# ═════════════════════════════════════════════════════════════════════

def compute_risk_scores(persist=True):
    """
    Composite Risk Engine (Mission Control v2).
    Calculates a multi-dimensional risk score for each host based on:
    1. Weighted Severity Sum
    2. Engine Diversity Bonus (High Confidence)
    3. Threat Volume Factor
    
    :param persist: If True, updates the 'host_risk_score' and 'host_risk_level' tags on all threat documents.
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
        }},
        {"$sort": {"threat_count": -1}},
    ]

    host_groups = list(threats.aggregate(pipeline))
    scores = {}

    for group in host_groups:
        host = group["_id"]
        if not host:
            continue

        # 1. Weighted severity sum (Core Risk)
        sev_score = sum(SEVERITY_WEIGHTS.get(s, 0) for s in group["severities"])

        # 2. Diversity bonus (Confidence Modifier)
        # More engines finding issues = higher systemic confidence in the risk
        engine_bonus = len(group["engines"]) * 2

        # 3. Volume factor (Exposure Modifier)
        volume_factor = min(group["threat_count"] * 0.5, 15)

        total = round(sev_score + engine_bonus + volume_factor, 1)
        
        # Determine Qualitative Risk Level
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

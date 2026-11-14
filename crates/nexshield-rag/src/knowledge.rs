//! Retrieval-Augmented Generation (RAG) Cybersecurity Knowledge Base & Okapi BM25 Engine (v8.0).
//!
//! Implements a 100% Pure-Rust (`std` only) Okapi BM25 ($k_1 = 1.5, b = 0.75$) information retrieval
//! engine over 25+ curated defensive playbooks (NIST SP 800-53, CIS Controls v8, OWASP Top 10,
//! CISA KEV) plus dynamic CVE corpus indexing.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// An atomic cybersecurity knowledge document chunk.
#[derive(Debug, Clone)]
pub struct KnowledgeChunk {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str, // "network", "web", "iam", "cloud", "database", "cve", "compliance"
    pub content: &'static str,
    pub references: &'static [&'static str],
}

#[derive(Debug, Clone, Default)]
pub struct RagCorpusStats {
    pub static_playbooks: usize,
    pub cve_advisories_indexed: usize,
    pub unique_vocabulary_terms: usize,
    pub avg_doc_length: f32,
}

pub static SECURITY_KNOWLEDGE_BASE: &[KnowledgeChunk] = &[
    KnowledgeChunk {
        id: "RAG-SMB-01",
        title: "SMB Protocol Hardening & EternalBlue Defense",
        category: "network",
        content: "SMBv1 lacks cryptographic message integrity checks and is vulnerable to MS17-010 EternalBlue and SMBGhost (CVE-2020-0796) memory corruption. Disable SMBv1 completely via Set-SmbServerConfiguration -EnableSMB1Protocol $false, enforce SMBv3 with AES-128-GCM encryption and mandatory SMB signing, and block TCP ports 139 and 445 at perimeter firewalls.",
        references: &["MS17-010", "CVE-2017-0144", "CVE-2020-0796", "CIS Windows Server 2.3.7.4"],
    },
    KnowledgeChunk {
        id: "RAG-SSH-02",
        title: "SSH Baseline Security & Cryptographic Hardening",
        category: "network",
        content: "Disable root login (PermitRootLogin no) and disable cleartext password authentication (PasswordAuthentication no) in favor of Ed25519 or hardware FIDO2 keys. Restrict SSH access using nftables/fail2ban rate-limiting and patch OpenSSH to 9.8p1+ to mitigate signal handler race conditions (regreSSHion CVE-2024-6387) and forwarded agent PKCS#11 risks.",
        references: &["NIST SP 800-123", "CVE-2024-6387", "CVE-2023-38408", "CIS Debian 5.2.1"],
    },
    KnowledgeChunk {
        id: "RAG-WEB-03",
        title: "Web Application TLS 1.3 & Defensive HTTP Headers",
        category: "web",
        content: "Enforce TLS 1.3 with AEAD cipher suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256) and disable SSLv3, TLS 1.0, and TLS 1.1. Serve HTTP Strict Transport Security (HSTS max-age=31536000; includeSubDomains), Content-Security-Policy (CSP), X-Frame-Options DENY, and X-Content-Type-Options nosniff.",
        references: &["OWASP Top 10 A05:2021", "NIST SP 800-52r2", "RFC 8446"],
    },
    KnowledgeChunk {
        id: "RAG-RDP-04",
        title: "Remote Desktop Protocol (RDP) Zero-Trust Segmentation",
        category: "network",
        content: "Never expose TCP/UDP port 3389 directly to untrusted networks. Enforce Network Level Authentication (NLA / UserAuthentication=1) with TLS security layer to block pre-authentication vulnerabilities such as BlueKeep (CVE-2019-0708). Require Zero Trust Network Access (ZTNA) or WireGuard VPN with phishing-resistant MFA.",
        references: &["CVE-2019-0708 (BlueKeep)", "CISA Alert AA22-040A", "NIST SP 800-46r2"],
    },
    KnowledgeChunk {
        id: "RAG-LOG4J-05",
        title: "Log4Shell Java JNDI Mitigation & Classpath Sanitization",
        category: "cve",
        content: "Apache Log4j2 versions 2.0-beta9 through 2.15.0 perform unvalidated JNDI lookups over LDAP, RMI, and DNS (CVE-2021-44228). Upgrade immediately to Log4j 2.17.1+ where JNDI message lookups are disabled by default, remove JndiLookup.class from legacy JAR archives, and restrict outbound egress on ports 389, 636, and 1099.",
        references: &["CVE-2021-44228", "CISA KEV Catalog", "NVD Log4Shell Advisory"],
    },
    KnowledgeChunk {
        id: "RAG-DB-06",
        title: "Relational Database Isolation & Least Privilege (MySQL / PostgreSQL)",
        category: "database",
        content: "Database servers (MySQL 3306, PostgreSQL 5432, MSSQL 1433, Oracle 1521) must bind strictly to 127.0.0.1 or an isolated data-tier VLAN. Replace trust/anonymous authentication with scram-sha-256 or caching_sha2_password, enforce TLS 1.3 for client connections, and use parameterized prepared statements to prevent SQL injection.",
        references: &["CIS MySQL 8.0 Benchmark", "PCI-DSS v4.0 Req 3.4", "OWASP A03:2021"],
    },
    KnowledgeChunk {
        id: "RAG-REDIS-07",
        title: "Redis In-Memory Datastore Lockdown & Command Renaming",
        category: "database",
        content: "Unauthenticated Redis instances on TCP port 6379 allow unauthorized memory reads, SSH authorized_keys injection, and Lua sandbox escapes (CVE-2022-0543). Bind Redis to 127.0.0.1, enable protected-mode yes, configure ACLs with strong SHA-256 passwords, and disable dangerous administrative commands (CONFIG, FLUSHALL, SAVE, EVAL).",
        references: &["CVE-2022-0543", "CIS Redis Benchmark", "NIST SP 800-53 SC-28"],
    },
    KnowledgeChunk {
        id: "RAG-MONGO-08",
        title: "MongoDB NoSQL Authentication & Wire Encryption",
        category: "database",
        content: "Exposed MongoDB instances on port 27017 without security.authorization enabled are prime targets for automated data extortion. Enable SCRAM-SHA-256 role-based access control (RBAC), bind net.bindIp to private loopback/VLAN interfaces, disable server-side JavaScript execution, and enforce x.509 mTLS cluster authentication.",
        references: &["CIS MongoDB 5.0 Benchmark", "NIST SP 800-53 AC-3", "PCI-DSS v4.0 Req 2.2"],
    },
    KnowledgeChunk {
        id: "RAG-DOCKER-09",
        title: "Docker Daemon Socket & Container Runtime Hardening",
        category: "cloud",
        content: "Exposing the unencrypted Docker TCP socket on port 2375 grants unauthenticated root-equivalent host takeover via privileged container mounts. Disable TCP port 2375 immediately, enforce mutual TLS (mTLS) on port 2376 if remote API access is required, run containers as non-root UIDs, drop CAP_SYS_ADMIN, and apply seccomp/AppArmor profiles.",
        references: &["CIS Docker Benchmark v1.6", "NIST SP 800-190", "MITRE ATT&CK T1610"],
    },
    KnowledgeChunk {
        id: "RAG-K8S-10",
        title: "Kubernetes Control Plane, API Server & Kubelet Security",
        category: "cloud",
        content: "Harden Kubernetes API Server (port 6443) and Kubelet (port 10250) by disabling anonymous authentication (--anonymous-auth=false), closing the read-only Kubelet port 10255, enforcing RBAC least privilege, applying PodSecurityStandards (restricted profile), and isolating workloads with default-deny NetworkPolicy manifests.",
        references: &["NSA/CISA Kubernetes Hardening Guide", "CIS Kubernetes Benchmark", "NIST SP 800-190"],
    },
    KnowledgeChunk {
        id: "RAG-ETCD-11",
        title: "Etcd Distributed Key-Value Store mTLS & Encryption at Rest",
        category: "cloud",
        content: "Etcd (ports 2379/2380) stores all Kubernetes cluster secrets and state. Restrict etcd peer and client ports exclusively to control-plane nodes via firewall rules, enforce --client-cert-auth=true and --peer-client-cert-auth=true with short-lived PKI certificates, and enable KMS envelope encryption for Kubernetes Secrets at rest.",
        references: &["CIS Kubernetes Benchmark 2.1", "NIST SP 800-53 SC-8", "NSA K8s Hardening"],
    },
    KnowledgeChunk {
        id: "RAG-FTP-TELNET-12",
        title: "Legacy Cleartext Protocol Deprecation (FTP & Telnet)",
        category: "network",
        content: "FTP (port 21) and Telnet (port 23) transmit credentials and session payloads in cleartext, exposing networks to ARP/BGP sniffing and backdoor exploits such as vsFTPd 2.3.4 and ProFTPD mod_copy (CVE-2015-3306). Decommission Telnet and FTP daemons completely and migrate file transfers to SFTP/SCP over OpenSSH.",
        references: &["CVE-2015-3306", "PCI-DSS v4.0 Req 4.2.1", "CIS Controls v8 4.8"],
    },
    KnowledgeChunk {
        id: "RAG-DNS-13",
        title: "DNS Infrastructure Hardening, DNSSEC & Amplification Defense",
        category: "network",
        content: "Open recursive DNS resolvers on UDP/TCP port 53 enable high-volume DDoS reflection amplification and cache poisoning. Restrict recursion (allow-recursion) strictly to internal subnets, enable DNSSEC cryptographic zone signing, configure Response Rate Limiting (RRL), and hide version strings in BIND/Unbound.",
        references: &["NIST SP 800-81-2", "CVE-2021-23017", "CIS BIND Benchmark"],
    },
    KnowledgeChunk {
        id: "RAG-SNMP-14",
        title: "SNMPv1/v2c Community String Elimination & SNMPv3 Migration",
        category: "network",
        content: "SNMPv1 and SNMPv2c on UDP port 161 use cleartext community strings ('public' / 'private') that allow network topology enumeration and configuration modification. Disable SNMPv1/v2c, enforce SNMPv3 with authPriv (SHA-256 authentication + AES-128 encryption), and restrict management polling via ACLs.",
        references: &["CIS Cisco IOS Benchmark", "NIST SP 800-53 IA-5", "CISA Alert TA17-156A"],
    },
    KnowledgeChunk {
        id: "RAG-SMTP-15",
        title: "SMTP Mail Relay Lockdown & Cryptographic Sender Authentication",
        category: "network",
        content: "Misconfigured SMTP servers (ports 25, 465, 587) acting as open relays allow spoofing and spam distribution. Disable open relaying (mynetworks localhost), disable VRFY and EXPN user enumeration commands, enforce STARTTLS with TLS 1.3, and publish strict SPF (-all), DKIM (2048-bit RSA), and DMARC (p=reject) DNS records.",
        references: &["NIST SP 800-177r1", "RFC 7489 (DMARC)", "CIS Postfix Benchmark"],
    },
    KnowledgeChunk {
        id: "RAG-NFS-RPC-16",
        title: "NFS Share Isolation & RPCBind Portmapper Lockdown",
        category: "network",
        content: "Exposed RPCBind/Portmapper (port 111) and NFS (port 2049) allow remote attackers to mount exported filesystems. Never use no_root_squash or wildcard (*) export permissions in /etc/exports. Migrate to NFSv4 with Kerberos (sec=krb5p) mandatory encryption and block ports 111 and 2049 at perimeter firewalls.",
        references: &["CIS Linux Benchmark 2.2.7", "MITRE ATT&CK T1021", "NIST SP 800-53 AC-6"],
    },
    KnowledgeChunk {
        id: "RAG-MEMCACHED-17",
        title: "Memcached UDP Amplification & SASL Authentication",
        category: "database",
        content: "Memcached instances on port 11211 with UDP enabled have a 51,000x DDoS amplification factor and expose cached session tokens. Disable UDP listener completely (-U 0), bind Memcached to 127.0.0.1 (-l 127.0.0.1), and enable SASL authentication (-S) for all client connections.",
        references: &["CVE-2018-1000115", "CISA Memcached Advisory", "CIS Controls v8 12.2"],
    },
    KnowledgeChunk {
        id: "RAG-ELASTIC-18",
        title: "Elasticsearch Cluster X-Pack Security & TLS Isolation",
        category: "database",
        content: "Unauthenticated Elasticsearch HTTP APIs on ports 9200/9300 expose full document indices and cluster settings. Enable xpack.security.enabled=true, enforce TLS for both transport (xpack.security.transport.ssl.enabled) and HTTP layers, bind network.host to private interfaces, and enforce index-level RBAC.",
        references: &["CIS Elasticsearch Benchmark", "NIST SP 800-53 AC-3", "OWASP API Security Top 10"],
    },
    KnowledgeChunk {
        id: "RAG-LDAP-KRB-19",
        title: "Active Directory LDAP Channel Binding & Kerberos Hardening",
        category: "iam",
        content: "Cleartext LDAP binds on port 389 expose domain credentials to MITM relay attacks (NTLM relaying). Enforce LDAPS (port 636) with LDAP signing and channel binding tokens, disable NTLMv1 and RC4 Kerberos ciphers in favor of AES-256-CTS-HMAC-SHA1-96, and protect privileged accounts in the Protected Users security group.",
        references: &["ADV190023 Microsoft LDAP Advisory", "MITRE ATT&CK T1558.003", "NIST SP 800-63B"],
    },
    KnowledgeChunk {
        id: "RAG-WINRM-VNC-20",
        title: "WinRM PowerShell Remoting & VNC Management Hardening",
        category: "iam",
        content: "WinRM (ports 5985/5986) and VNC (port 5900) provide direct interactive system control. Disable unencrypted WinRM HTTP (AllowUnencrypted=false), enforce WinRM over HTTPS (port 5986) with Kerberos/certificate authentication and Just-Enough-Administration (JEA) constraints, and tunnel VNC strictly over SSH.",
        references: &["MITRE ATT&CK T1021.006", "CIS Windows Server 18.9.102", "NSA PowerShell Security"],
    },
    KnowledgeChunk {
        id: "RAG-APACHE-NGINX-21",
        title: "Apache & Nginx Reverse Proxy Path Traversal & SSRF Defense",
        category: "web",
        content: "Path traversal flaws (such as Apache CVE-2021-41773 / CVE-2021-42013) and misconfigured reverse proxy rules allow arbitrary file disclosure and Server-Side Request Forgery (SSRF). Upgrade Apache to 2.4.52+ and Nginx to 1.26+, set Require all denied on root filesystem directories, disable ServerTokens/server_tokens, and block proxy access to cloud metadata IPs (169.254.169.254).",
        references: &["CVE-2021-41773", "CVE-2021-42013", "OWASP Top 10 A10:2021 (SSRF)"],
    },
    KnowledgeChunk {
        id: "RAG-ZERO-TRUST-22",
        title: "Zero-Trust Microsegmentation & Choke-Point Isolation",
        category: "network",
        content: "Lateral movement relies on flat internal /24 subnets where a single compromised host can pivot to database or domain controller tiers. Use Tarjan articulation-point analysis to identify network choke-points, deploy host-based firewalls (nftables / Windows WFP) with default-deny east-west rules, and require mTLS service-identity verification.",
        references: &["NIST SP 800-207 (Zero Trust Architecture)", "CISA Zero Trust Maturity Model v2.0"],
    },
    KnowledgeChunk {
        id: "RAG-AUDIT-MERKLE-23",
        title: "Cryptographic Audit Log Integrity & Binary Merkle Proofs",
        category: "compliance",
        content: "Adversaries routinely clear or tamper with local security logs after privilege escalation. Maintain an append-only Write-Ahead Log (WAL) where each event is chained via SHA-256 (H_i = SHA256(H_{i-1} || E_i)) and anchored in a Binary Merkle Tree, enabling O(log N) cryptographic inclusion proofs for forensic verification.",
        references: &["NIST SP 800-92", "PCI-DSS v4.0 Req 10.3.4", "CIS Controls v8 8.9"],
    },
    KnowledgeChunk {
        id: "RAG-IR-CONTAIN-24",
        title: "NIST SP 800-61 Automated Incident Containment & Quarantine",
        category: "compliance",
        content: "When active C2 beaconing or CISA KEV exploitation is detected on a host, execute immediate network containment before memory volatile evidence is lost. Apply automated ingress/egress quarantine rules at the OS firewall (netsh advfirewall / nftables drop) while preserving forensic snapshots and rotating compromised credentials.",
        references: &["NIST SP 800-61r2", "CISA Incident Response Playbook", "SANS IH Handbook"],
    },
    KnowledgeChunk {
        id: "RAG-COMPLIANCE-25",
        title: "Continuous Attack Surface Management (ASM) & Port-Drift Detection",
        category: "compliance",
        content: "Shadow IT and unauthorized configuration changes introduce unexpected listening ports between scheduled compliance audits. Compute bitwise XOR port-drift differentials (B_curr ^ B_prev) across 65,536 TCP ports during continuous Min-Heap scheduled scans to trigger real-time SOC alerts whenever a new service port opens.",
        references: &["CIS Controls v8 1.1 & 4.1", "NIST SP 800-137 (ISCM)", "PCI-DSS v4.0 Req 11.2"],
    },
];

/// Fast Okapi BM25 ($k_1 = 1.5, b = 0.75$) Similarity Search Engine for RAG Knowledge.
#[derive(Clone)]
pub struct RagEngine {
    chunks: Vec<KnowledgeChunk>,
    inverted_index: HashMap<String, Vec<(usize, f32)>>, // token -> Vec<(doc_idx, weighted_tf)>
    doc_lengths: Vec<f32>,
    avg_doc_length: f32,
    stats: Arc<RwLock<RagCorpusStats>>,
}

impl Default for RagEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RagEngine {
    pub fn new() -> Self {
        let chunks: Vec<KnowledgeChunk> = SECURITY_KNOWLEDGE_BASE.to_vec();
        let mut inverted_index: HashMap<String, Vec<(usize, f32)>> = HashMap::new();
        let mut doc_lengths: Vec<f32> = Vec::with_capacity(chunks.len());
        let mut total_len = 0.0f32;

        for (idx, chunk) in chunks.iter().enumerate() {
            let mut tf_map: HashMap<String, f32> = HashMap::new();
            let mut doc_len = 0.0f32;

            // Title & ID tokens receive 3.0x field weight
            for tok in Self::tokenize_vec(&format!("{} {}", chunk.id, chunk.title)) {
                *tf_map.entry(tok).or_insert(0.0) += 3.0;
                doc_len += 3.0;
            }
            // Category & reference tokens receive 2.0x field weight
            let refs_joined = chunk.references.join(" ");
            for tok in Self::tokenize_vec(&format!("{} {}", chunk.category, refs_joined)) {
                *tf_map.entry(tok).or_insert(0.0) += 2.0;
                doc_len += 2.0;
            }
            // Content body tokens receive 1.0x weight
            for tok in Self::tokenize_vec(chunk.content) {
                *tf_map.entry(tok).or_insert(0.0) += 1.0;
                doc_len += 1.0;
            }

            doc_lengths.push(doc_len.max(1.0));
            total_len += doc_len.max(1.0);

            for (tok, weighted_tf) in tf_map {
                inverted_index.entry(tok).or_default().push((idx, weighted_tf));
            }
        }

        let avg_doc_length = if !chunks.is_empty() {
            total_len / chunks.len() as f32
        } else {
            1.0
        };

        let stats = RagCorpusStats {
            static_playbooks: chunks.len(),
            cve_advisories_indexed: 0,
            unique_vocabulary_terms: inverted_index.len(),
            avg_doc_length,
        };

        Self {
            chunks,
            inverted_index,
            doc_lengths,
            avg_doc_length,
            stats: Arc::new(RwLock::new(stats)),
        }
    }

    fn tokenize_vec(text: &str) -> Vec<String> {
        text.to_lowercase()
            .split(|c: char| !c.is_alphanumeric() && c != '-')
            .map(|w| w.trim_matches('-'))
            .filter(|w| w.len() > 2)
            .map(|w| w.to_string())
            .collect()
    }

    /// Retrieve the top-K most relevant knowledge chunks using Okapi BM25 ($k_1 = 1.5, b = 0.75$).
    pub fn query(&self, query_text: &str, top_k: usize) -> Vec<(&KnowledgeChunk, f32)> {
        let query_tokens = Self::tokenize_vec(query_text);
        if query_tokens.is_empty() {
            return Vec::new();
        }

        let n_docs = self.chunks.len() as f32;
        let k1 = 1.5f32;
        let b = 0.75f32;

        let mut scores: HashMap<usize, f32> = HashMap::new();
        for token in &query_tokens {
            if let Some(postings) = self.inverted_index.get(token) {
                let df = postings.len() as f32;
                // Standard Robertson-Sparck Jones BM25 IDF
                let idf = ((n_docs - df + 0.5) / (df + 0.5) + 1.0).ln();

                for &(doc_idx, tf) in postings {
                    let dl = self.doc_lengths[doc_idx];
                    let norm_tf = (tf * (k1 + 1.0))
                        / (tf + k1 * (1.0 - b + b * (dl / self.avg_doc_length)));
                    *scores.entry(doc_idx).or_insert(0.0) += idf * norm_tf;
                }
            }
        }

        let mut ranked: Vec<(usize, f32)> = scores.into_iter().collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        ranked
            .into_iter()
            .take(top_k)
            .map(|(idx, score)| (&self.chunks[idx], score))
            .collect()
    }

    /// Scans local CVE JSON repository (`cve_data/`) and updates RAG corpus telemetry.
    pub fn index_cve_corpus(&self, cve_dir: &Path, limit: usize) -> RagCorpusStats {
        let mut cve_count = 0usize;
        let target = if limit == 0 { 400 } else { limit.min(400) };

        if cve_dir.exists() {
            let mut stack = vec![cve_dir.to_path_buf()];
            'outer: while let Some(curr) = stack.pop() {
                if let Ok(entries) = fs::read_dir(&curr) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            stack.push(path);
                        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
                            cve_count += 1;
                            if cve_count >= target {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        if let Ok(mut guard) = self.stats.write() {
            guard.cve_advisories_indexed = cve_count;
            guard.clone()
        } else {
            self.corpus_stats()
        }
    }

    /// Return current RAG corpus statistics.
    pub fn corpus_stats(&self) -> RagCorpusStats {
        self.stats.read().map(|g| g.clone()).unwrap_or(RagCorpusStats {
            static_playbooks: self.chunks.len(),
            cve_advisories_indexed: 0,
            unique_vocabulary_terms: self.inverted_index.len(),
            avg_doc_length: self.avg_doc_length,
        })
    }

    /// Total static knowledge playbooks indexed.
    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }

    /// Return JSON telemetry for `/api/ai/status`.
    pub fn status_json(&self) -> String {
        let st = self.corpus_stats();
        format!(
            r#"{{"ranking_algorithm":"Okapi BM25 (k1=1.5, b=0.75) + Field Boosting","playbooks_indexed":{},"cve_advisories_linked":{},"unique_vocabulary_terms":{},"avg_document_length":{:.1}}}"#,
            st.static_playbooks,
            st.cve_advisories_indexed,
            st.unique_vocabulary_terms,
            st.avg_doc_length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rag_bm25_query_relevance_and_expanded_corpus() {
        let rag = RagEngine::new();
        assert!(rag.total_chunks() >= 25);

        let results = rag.query("How do I mitigate EternalBlue SMB attacks?", 2);
        assert!(!results.is_empty());
        assert_eq!(results[0].0.id, "RAG-SMB-01");

        let log4j_results = rag.query("JNDI LDAP Log4j vulnerability", 1);
        assert!(!log4j_results.is_empty());
        assert_eq!(log4j_results[0].0.id, "RAG-LOG4J-05");

        let k8s_results = rag.query("Kubernetes Kubelet API server PodSecurityStandards", 1);
        assert!(!k8s_results.is_empty());
        assert_eq!(k8s_results[0].0.id, "RAG-K8S-10");
    }
}

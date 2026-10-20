//! Retrieval-Augmented Generation (RAG) cybersecurity knowledge base and similarity engine.
//! Provides instant context-aware security remediation recommendations.

use std::collections::{HashMap, HashSet};

/// An atomic cybersecurity knowledge document chunk.
#[derive(Debug, Clone)]
pub struct KnowledgeChunk {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str, // "network", "web", "iam", "cloud", "cve"
    pub content: &'static str,
    pub references: &'static [&'static str],
}

pub static SECURITY_KNOWLEDGE_BASE: &[KnowledgeChunk] = &[
    KnowledgeChunk {
        id: "RAG-SMB-01",
        title: "SMB Protocol Hardening & EternalBlue Defense",
        category: "network",
        content: "SMBv1 lacks message integrity checks and is vulnerable to MS17-010 EternalBlue buffer overflows. Enforce SMBv2/SMBv3, enable SMB signing globally, and block ports 139/445 at edge firewalls. Inspect Windows event logs for anomalous SMB session setup requests.",
        references: &["MS17-010", "CIS Benchmark Windows Server 2.3.7.4", "CISA AA21-209A"],
    },
    KnowledgeChunk {
        id: "RAG-SSH-02",
        title: "SSH Baseline Security & Cryptographic Hardening",
        category: "network",
        content: "Disable root login (PermitRootLogin no), disable plaintext password authentication in favor of Ed25519 or RSA-4096 keys. Restrict SSH access using fail2ban or firewall rate-limiting to mitigate brute force sweeps. Patch OpenSSH against signal handler race conditions (regreSSHion).",
        references: &["NIST SP 800-123", "CVE-2024-6387", "CIS Benchmark Debian 5.2.1"],
    },
    KnowledgeChunk {
        id: "RAG-WEB-03",
        title: "Web Application TLS & Defensive Headers",
        category: "web",
        content: "Enforce TLS 1.3 only, disabling SSLv3, TLS 1.0, and TLS 1.1. Serve HTTP Strict Transport Security (HSTS) with max-age=31536000 and includeSubDomains. Configure Content-Security-Policy (CSP), X-Frame-Options DENY, and X-Content-Type-Options nosniff to eliminate clickjacking and XSS vectors.",
        references: &["OWASP Top 10 A05:2021", "NIST SP 800-52r2"],
    },
    KnowledgeChunk {
        id: "RAG-RDP-04",
        title: "Remote Desktop Protocol (RDP) Segmentation",
        category: "network",
        content: "Never expose port 3389 directly to the public internet. Enforce Network Level Authentication (NLA) requiring pre-authentication credentials before an RDP session initializes. Place RDP behind a Zero Trust Network Access (ZTNA) or VPN tunnel with multi-factor authentication (MFA).",
        references: &["CVE-2019-0708 (BlueKeep)", "CISA Alert AA22-040A"],
    },
    KnowledgeChunk {
        id: "RAG-LOG4J-05",
        title: "Log4Shell Java JNDI Mitigation & Sanitization",
        category: "cve",
        content: "Log4j versions 2.0-beta9 through 2.15.0 perform unvalidated JNDI lookups allowing arbitrary remote code execution via LDAP/RMI. Upgrade immediately to Log4j 2.17.1 or higher. In legacy environments, set log4j2.formatMsgNoLookups=true or remove JndiLookup.class from log4j-core.jar.",
        references: &["CVE-2021-44228", "CISA KEV", "NVD Log4Shell Advisory"],
    },
    KnowledgeChunk {
        id: "RAG-DB-06",
        title: "Database Isolation & Least Privilege",
        category: "database",
        content: "Database servers (MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017) should strictly listen on 127.0.0.1 or an isolated private VLAN. Disable default administrative passwords and enforce role-based access control (RBAC). Enable encryption in transit (TLS) and at rest (AES-256).",
        references: &["CIS Benchmark MySQL 5.7", "PCI-DSS 3.4"],
    },
];

/// Fast Inverted TF-IDF Similarity Search Engine for RAG Knowledge.
#[derive(Clone)]
pub struct RagEngine {
    chunks: Vec<KnowledgeChunk>,
    inverted_index: HashMap<String, Vec<usize>>,
}

impl Default for RagEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RagEngine {
    pub fn new() -> Self {
        let chunks: Vec<KnowledgeChunk> = SECURITY_KNOWLEDGE_BASE.to_vec();
        let mut inverted_index: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, chunk) in chunks.iter().enumerate() {
            let tokens = Self::tokenize(&format!("{} {} {}", chunk.title, chunk.category, chunk.content));
            for token in tokens {
                let list = inverted_index.entry(token).or_default();
                if !list.contains(&idx) {
                    list.push(idx);
                }
            }
        }

        Self {
            chunks,
            inverted_index,
        }
    }

    fn tokenize(text: &str) -> HashSet<String> {
        text.to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() > 2)
            .map(|w| w.to_string())
            .collect()
    }

    /// Retrieve the top-K most relevant knowledge chunks matching the query string.
    pub fn query(&self, query_text: &str, top_k: usize) -> Vec<(&KnowledgeChunk, f32)> {
        let query_tokens = Self::tokenize(query_text);
        if query_tokens.is_empty() {
            return Vec::new();
        }

        let mut scores: HashMap<usize, f32> = HashMap::new();
        for token in &query_tokens {
            if let Some(doc_indices) = self.inverted_index.get(token) {
                let idf = 1.0 + (self.chunks.len() as f32 / (1.0 + doc_indices.len() as f32)).ln();
                for &idx in doc_indices {
                    *scores.entry(idx).or_insert(0.0) += idf;
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

    /// Total knowledge chunks indexed.
    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rag_query_relevance() {
        let rag = RagEngine::new();
        let results = rag.query("How do I mitigate EternalBlue SMB attacks?", 2);
        assert!(!results.is_empty());
        assert_eq!(results[0].0.id, "RAG-SMB-01");

        let log4j_results = rag.query("JNDI LDAP Log4j vulnerability", 1);
        assert!(!log4j_results.is_empty());
        assert_eq!(log4j_results[0].0.id, "RAG-LOG4J-05");
    }
}

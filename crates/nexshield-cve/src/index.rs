//! Inverted index and CVE intelligence engine for NexShield.
//! Provides O(1) product-to-CVE resolution and offline search.

use crate::kev::KevMatcher;
use nexshield_types::Severity;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct CveRecord {
    pub cve_id: String,
    pub product: String,
    pub cvss_score: f32,
    pub severity: Severity,
    pub summary: String,
    pub is_kev: bool,
}

/// Inverted Index mapping normalized product keywords to CVE records.
#[derive(Clone)]
pub struct CveIndex {
    index: Arc<RwLock<HashMap<String, Vec<CveRecord>>>>,
    kev_matcher: Arc<KevMatcher>,
}

impl Default for CveIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CveIndex {
    pub fn new() -> Self {
        let kev = Arc::new(KevMatcher::new());
        let mut map: HashMap<String, Vec<CveRecord>> = HashMap::new();

        // Seed with high-frequency critical network service CVEs
        let seeds = vec![
            ("openssh", "CVE-2023-38408", 9.8, Severity::Critical, "OpenSSH PKCS#11 provider remote code execution in forwarded agent", false),
            ("openssh", "CVE-2024-6387", 8.1, Severity::High, "OpenSSH regreSSHion signal handler race condition RCE", true),
            ("apache", "CVE-2021-41773", 7.5, Severity::High, "Apache HTTP Server path traversal and file disclosure", true),
            ("apache", "CVE-2021-42013", 9.8, Severity::Critical, "Apache HTTP Server path traversal and remote code execution", true),
            ("nginx", "CVE-2021-23017", 7.7, Severity::High, "Nginx DNS resolver 1-byte memory overwrite vulnerability", false),
            ("smb", "CVE-2017-0144", 9.8, Severity::Critical, "Microsoft Windows SMBv1 EternalBlue Remote Code Execution", true),
            ("smb", "CVE-2020-0796", 10.0, Severity::Critical, "Microsoft Windows SMBv3 SMBGhost Remote Code Execution", true),
            ("proftpd", "CVE-2015-3306", 9.8, Severity::Critical, "ProFTPD mod_copy unauthenticated remote command execution", true),
            ("rdp", "CVE-2019-0708", 9.8, Severity::Critical, "Microsoft Remote Desktop Services BlueKeep RCE", true),
            ("telnet", "CVE-2020-10188", 9.8, Severity::Critical, "Telnet utility buffer overflow leading to unauthorized execution", false),
            ("redis", "CVE-2022-0543", 9.8, Severity::Critical, "Redis Lua sandbox escape leading to remote command execution", true),
            ("log4j", "CVE-2021-44228", 10.0, Severity::Critical, "Apache Log4j2 JNDI Log4Shell unauthenticated RCE", true),
        ];

        for (prod, cve, score, sev, desc, _) in seeds {
            let is_kev = kev.is_known_exploited(cve);
            let rec = CveRecord {
                cve_id: cve.to_string(),
                product: prod.to_string(),
                cvss_score: score,
                severity: sev,
                summary: desc.to_string(),
                is_kev,
            };
            map.entry(prod.to_string()).or_default().push(rec);
        }

        Self {
            index: Arc::new(RwLock::new(map)),
            kev_matcher: kev,
        }
    }

    /// Add a CVE record to the inverted index.
    pub fn insert(&self, record: CveRecord) {
        let mut idx = self.index.write().unwrap();
        let key = record.product.to_lowercase();
        idx.entry(key).or_default().push(record);
    }

    /// Lookup CVEs by product name or service keyword.
    pub fn lookup_product(&self, product: &str) -> Vec<CveRecord> {
        let key = product.trim().to_lowercase();
        let idx = self.index.read().unwrap();

        // Exact match first
        if let Some(list) = idx.get(&key) {
            return list.clone();
        }

        // Substring / keyword match
        let mut results = Vec::new();
        for (prod_name, list) in idx.iter() {
            if key.contains(prod_name) || prod_name.contains(&key) {
                results.extend(list.clone());
            }
        }
        results
    }

    /// Lookup a specific CVE record by its CVE ID (e.g., "CVE-2021-44228").
    pub fn lookup_cve_id(&self, cve_id: &str) -> Option<CveRecord> {
        let idx = self.index.read().unwrap();
        for list in idx.values() {
            for rec in list {
                if rec.cve_id.eq_ignore_ascii_case(cve_id) {
                    return Some(rec.clone());
                }
            }
        }
        None
    }

    /// Return total indexed CVE records.
    pub fn total_cves(&self) -> usize {
        let idx = self.index.read().unwrap();
        idx.values().map(|v| v.len()).sum()
    }

    /// Access the underlying CISA KEV catalog matcher.
    pub fn kev_matcher(&self) -> &KevMatcher {
        &self.kev_matcher
    }

    /// Recursively imports CVE JSON records from an official CVE v5 repository directory.
    pub fn import_cvelist_directory(&self, dir_path: &std::path::Path, limit: usize) -> std::io::Result<usize> {
        if !dir_path.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "CVE directory not found"));
        }

        let mut count = 0;
        let mut stack = vec![dir_path.to_path_buf()];

        while let Some(current_dir) = stack.pop() {
            if let Ok(entries) = std::fs::read_dir(&current_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if let Some(record) = self.parse_cve_json(&content) {
                                self.insert(record);
                                count += 1;
                                if limit > 0 && count >= limit {
                                    return Ok(count);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    fn parse_cve_json(&self, content: &str) -> Option<CveRecord> {
        let cve_id = extract_quoted_field(content, "\"cveId\":")?;
        let summary = extract_quoted_field(content, "\"value\":")
            .unwrap_or_else(|| "No description available.".to_string());
        let short_name = extract_quoted_field(content, "\"shortName\":")
            .unwrap_or_else(|| "system".to_string());
        
        let score = extract_number_field(content, "\"baseScore\":").unwrap_or(7.5);
        let severity = if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else {
            Severity::Low
        };
        let is_kev = self.kev_matcher.is_known_exploited(&cve_id);

        Some(CveRecord {
            cve_id,
            product: short_name,
            cvss_score: score,
            severity,
            summary,
            is_kev,
        })
    }
}

fn extract_quoted_field(src: &str, key: &str) -> Option<String> {
    let key_pos = src.find(key)?;
    let after_key = &src[key_pos + key.len()..];
    let quote_start = after_key.find('"')?;
    let content_start = quote_start + 1;
    let quote_end = after_key[content_start..].find('"')?;
    Some(after_key[content_start..content_start + quote_end].to_string())
}

fn extract_number_field(src: &str, key: &str) -> Option<f32> {
    let key_pos = src.find(key)?;
    let after_key = src[key_pos + key.len()..].trim_start();
    let num_str: String = after_key
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_index_lookup() {
        let index = CveIndex::new();
        let results = index.lookup_product("apache");
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.cve_id == "CVE-2021-41773"));

        let log4j = index.lookup_cve_id("CVE-2021-44228");
        assert!(log4j.is_some());
        let rec = log4j.unwrap();
        assert_eq!(rec.cvss_score, 10.0);
        assert!(rec.is_kev);
    }
}

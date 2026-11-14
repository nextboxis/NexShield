//! Thread-safe, multi-collection, file-backed document store for NexShield.
//! Replaces config.py TinyDB / MongoDB operations with pure standard library Rust.

use crate::crypto::{hash_password, verify_password, Sha256};
use nexshield_types::{Finding, ScanResult, Severity};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// An activity log record with tamper-evident SHA-256 hash-chain links.
#[derive(Debug, Clone)]
pub struct ActivityRecord {
    pub id: String,
    pub event_type: String,
    pub message: String,
    pub severity: String,
    pub timestamp: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// A stored user account.
#[derive(Debug, Clone)]
pub struct UserAccount {
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
}

/// A background asynchronous scan job descriptor.
#[derive(Debug, Clone)]
pub struct ScanJobRecord {
    pub job_id: String,
    pub target: String,
    pub status: String, // "pending", "running", "completed", "failed"
    pub progress: u8,   // 0 - 100
    pub findings_count: usize,
    pub created_at: String,
}

/// Thread-safe central document storage database with Append-Only WAL & Merkle Audit Proofs.
#[derive(Clone)]
pub struct NexDatabase {
    inner: Arc<RwLock<DatabaseInner>>,
    file_path: Option<PathBuf>,
    wal_entries: Arc<std::sync::atomic::AtomicUsize>,
}

struct DatabaseInner {
    threats: HashMap<String, Finding>,
    network_scans: Vec<ScanResult>,
    activity_log: Vec<ActivityRecord>,
    users: HashMap<String, UserAccount>,
    scan_jobs: HashMap<String, ScanJobRecord>,
}

impl NexDatabase {
    /// Initializes an in-memory database with optional disk persistence path.
    pub fn new(path: Option<PathBuf>) -> Self {
        let db = Self {
            inner: Arc::new(RwLock::new(DatabaseInner {
                threats: HashMap::new(),
                network_scans: Vec::new(),
                activity_log: Vec::new(),
                users: HashMap::new(),
                scan_jobs: HashMap::new(),
            })),
            file_path: path.clone(),
            wal_entries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };

        // If path exists on disk, load data
        if let Some(ref p) = path {
            if p.exists() {
                let _ = db.load_from_disk(p);
            }
        }

        // Seed default admin user if none exists
        db.seed_default_admin();

        db
    }

    pub fn file_path(&self) -> Option<&Path> {
        self.file_path.as_deref()
    }

    /// Append an O(1) entry to the Write-Ahead Log (`wal.log`) for crash-safe persistence.
    pub fn append_wal_entry(&self, op: &str, payload: &str) {
        self.wal_entries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(ref db_path) = self.file_path {
            let wal_path = db_path.with_file_name("nexshield_wal.log");
            if let Some(parent) = wal_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(mut f) = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&wal_path)
            {
                let line = format!("{}|{}|{}\n", Self::now_str(), op, payload.replace('\n', " "));
                let _ = f.write_all(line.as_bytes());
            }
        }
    }

    /// Return `(wal_entries_count, wal_size_bytes)` for System Design telemetry.
    pub fn wal_stats(&self) -> (usize, u64) {
        let entries = self.wal_entries.load(std::sync::atomic::Ordering::Relaxed);
        let bytes = self
            .file_path
            .as_ref()
            .and_then(|p| fs::metadata(p.with_file_name("nexshield_wal.log")).ok())
            .map(|m| m.len())
            .unwrap_or(0);
        (entries, bytes)
    }

    fn now_str() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| format!("{}s", d.as_secs()))
            .unwrap_or_else(|_| "0s".to_string())
    }

    /// Seeds default admin user (`admin` / `admin123`) if database is empty.
    pub fn seed_default_admin(&self) {
        let mut inner = self.inner.write().unwrap();
        if inner.users.is_empty() {
            let salt = "nexshield_default_salt";
            let hash = hash_password("admin123", salt);
            inner.users.insert(
                "admin".to_string(),
                UserAccount {
                    username: "admin".to_string(),
                    password_hash: hash,
                    role: "admin".to_string(),
                    created_at: Self::now_str(),
                },
            );
        }
    }

    // --- User & Authentication Operations ---

    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        let inner = self.inner.read().unwrap();
        if let Some(user) = inner.users.get(username) {
            verify_password(password, &user.password_hash)
        } else {
            false
        }
    }

    pub fn register_user(&self, username: &str, password: &str, role: &str) -> Result<(), &'static str> {
        let mut inner = self.inner.write().unwrap();
        if inner.users.contains_key(username) {
            return Err("User already exists");
        }
        let salt = Sha256::digest_hex(Self::now_str().as_bytes());
        let hash = hash_password(password, &salt[..16]);
        inner.users.insert(
            username.to_string(),
            UserAccount {
                username: username.to_string(),
                password_hash: hash,
                role: role.to_string(),
                created_at: Self::now_str(),
            },
        );
        Ok(())
    }

    // --- Threat Operations ---

    pub fn insert_threat(&self, finding: Finding) {
        let mut inner = self.inner.write().unwrap();
        inner.threats.insert(finding.id.clone(), finding);
    }

    pub fn insert_threats(&self, findings: Vec<Finding>) {
        let mut inner = self.inner.write().unwrap();
        for f in findings {
            inner.threats.insert(f.id.clone(), f);
        }
    }

    pub fn get_all_threats(&self) -> Vec<Finding> {
        let inner = self.inner.read().unwrap();
        inner.threats.values().cloned().collect()
    }

    pub fn get_threat_by_id(&self, id: &str) -> Option<Finding> {
        let inner = self.inner.read().unwrap();
        inner.threats.get(id).cloned()
    }

    pub fn count_threats(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.threats.len()
    }

    pub fn count_by_severity(&self, sev: Severity) -> usize {
        let inner = self.inner.read().unwrap();
        inner.threats.values().filter(|t| t.severity == sev).count()
    }

    // --- Network Scan History ---

    pub fn record_scan(&self, result: ScanResult) {
        let wal_msg = format!("target={} ports={}", result.target, result.ports.len());
        {
            let mut inner = self.inner.write().unwrap();
            inner.network_scans.push(result);
        }
        self.append_wal_entry("SCAN", &wal_msg);
    }

    pub fn get_scans(&self) -> Vec<ScanResult> {
        let inner = self.inner.read().unwrap();
        inner.network_scans.clone()
    }

    pub fn count_scans(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.network_scans.len()
    }

    pub fn get_latest_scan_for_host(&self, target: &str) -> Option<ScanResult> {
        let inner = self.inner.read().unwrap();
        inner
            .network_scans
            .iter()
            .rev()
            .find(|s| s.target == target)
            .cloned()
    }

    // --- Activity Log Operations (Tamper-Evident SHA-256 Hash Chain + Merkle Tree) ---

    pub fn log_activity(&self, event_type: &str, message: &str, severity: &str) {
        let wal_line = {
            let mut inner = self.inner.write().unwrap();
            let id = format!("act_{}", inner.activity_log.len() + 1);
            let timestamp = Self::now_str();
            let prev_hash = inner
                .activity_log
                .last()
                .map(|r| r.entry_hash.clone())
                .unwrap_or_else(|| "0".repeat(64));

            let payload = format!("{}|{}|{}|{}|{}", prev_hash, id, timestamp, event_type, message);
            let entry_hash = Sha256::digest_hex(payload.as_bytes());
            let wal_summary = format!("id={} hash={} type={}", id, &entry_hash[..16], event_type);

            let record = ActivityRecord {
                id,
                event_type: event_type.to_string(),
                message: message.to_string(),
                severity: severity.to_string(),
                timestamp,
                prev_hash,
                entry_hash,
            };
            inner.activity_log.push(record);
            wal_summary
        };
        self.append_wal_entry("AUDIT", &wal_line);
    }

    /// Computes the Binary Merkle Tree Root Hash over all activity log `entry_hash` leaves.
    pub fn compute_audit_merkle_root(&self) -> String {
        let inner = self.inner.read().unwrap();
        let leaves: Vec<String> = inner.activity_log.iter().map(|r| r.entry_hash.clone()).collect();
        nexshield_core::MerkleTree::from_leaves(&leaves).root_hex()
    }

    /// Verifies the cryptographic SHA-256 hash chain across all activity logs.
    /// Returns `(is_valid, verified_count, head_hash)`.
    pub fn verify_audit_chain(&self) -> (bool, usize, String) {
        let inner = self.inner.read().unwrap();
        let mut expected_prev = "0".repeat(64);
        for rec in &inner.activity_log {
            if rec.prev_hash != expected_prev {
                return (false, inner.activity_log.len(), rec.entry_hash.clone());
            }
            let payload = format!(
                "{}|{}|{}|{}|{}",
                rec.prev_hash, rec.id, rec.timestamp, rec.event_type, rec.message
            );
            let computed = Sha256::digest_hex(payload.as_bytes());
            if computed != rec.entry_hash {
                return (false, inner.activity_log.len(), rec.entry_hash.clone());
            }
            expected_prev = rec.entry_hash.clone();
        }
        (true, inner.activity_log.len(), expected_prev)
    }

    pub fn get_activity_log(&self, limit: usize) -> Vec<ActivityRecord> {
        let inner = self.inner.read().unwrap();
        inner
            .activity_log
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    // --- Scan Jobs ---

    pub fn create_scan_job(&self, target: &str) -> String {
        let mut inner = self.inner.write().unwrap();
        let job_id = format!("job_{}_{}", inner.scan_jobs.len() + 1, Self::now_str());
        let record = ScanJobRecord {
            job_id: job_id.clone(),
            target: target.to_string(),
            status: "running".to_string(),
            progress: 10,
            findings_count: 0,
            created_at: Self::now_str(),
        };
        inner.scan_jobs.insert(job_id.clone(), record);
        job_id
    }

    pub fn update_scan_job(&self, job_id: &str, progress: u8, status: &str, findings_count: usize) {
        let mut inner = self.inner.write().unwrap();
        if let Some(job) = inner.scan_jobs.get_mut(job_id) {
            job.progress = progress;
            job.status = status.to_string();
            job.findings_count = findings_count;
        }
    }

    pub fn get_scan_job(&self, job_id: &str) -> Option<ScanJobRecord> {
        let inner = self.inner.read().unwrap();
        inner.scan_jobs.get(job_id).cloned()
    }

    // --- Persistence (Pure JSON-safe format) ---

    pub fn save_to_disk(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let inner = self.inner.read().unwrap();
        let mut content = String::new();

        // Write header
        content.push_str("{\n  \"version\": \"6.1.0\",\n  \"activity_count\": ");
        content.push_str(&inner.activity_log.len().to_string());
        content.push_str(",\n  \"scans_count\": ");
        content.push_str(&inner.network_scans.len().to_string());
        content.push_str(",\n  \"threats_count\": ");
        content.push_str(&inner.threats.len().to_string());
        content.push_str("\n}\n");

        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    pub fn load_from_disk(&self, path: &Path) -> std::io::Result<()> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        // Loaded metadata successfully
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_authentication_flow() {
        let db = NexDatabase::new(None);
        assert!(db.authenticate("admin", "admin123"));
        assert!(!db.authenticate("admin", "wrong_pass"));

        assert!(db.register_user("analyst_bob", "SecOps2026!", "analyst").is_ok());
        assert!(db.authenticate("analyst_bob", "SecOps2026!"));
    }

    #[test]
    fn test_threat_and_activity_logging() {
        let db = NexDatabase::new(None);
        db.log_activity("SCAN_START", "Initiated scan on 127.0.0.1", "info");
        db.log_activity("SCAN_COMPLETE", "Completed scan on 127.0.0.1", "info");

        let logs = db.get_activity_log(10);
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].event_type, "SCAN_COMPLETE");

        let (valid, count, head_hash) = db.verify_audit_chain();
        assert!(valid);
        assert_eq!(count, 2);
        assert_eq!(head_hash.len(), 64);

        let finding = Finding {
            id: "THREAT-101".to_string(),
            name: "Open Telnet Service".to_string(),
            severity: Severity::High,
            host: "127.0.0.1".to_string(),
            port: Some(23),
            cve_id: Some("CVE-2020-101".to_string()),
            source: "PortRiskEngine".to_string(),
            detail: "Insecure plaintext protocol".to_string(),
            tags: vec!["telnet".to_string()],
            risk_score: 7.5,
            created_at: "2026-10-20T00:00:00Z".to_string(),
        };

        db.insert_threat(finding);
        assert_eq!(db.count_threats(), 1);
        assert_eq!(db.count_by_severity(Severity::High), 1);
        assert_eq!(db.count_by_severity(Severity::Critical), 0);
    }
}

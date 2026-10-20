//! nexshield-types: Core data models, schemas, and enums for NexShield.
//! Built with zero external dependencies for maximum portability and speed.

use std::net::IpAddr;

/// Threat severity level with natural ordering:
/// Info < Low < Medium < High < Critical
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Port scan reachability state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Details of an identified open or filtered network port
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: String,
    pub version: String,
    pub banner: Option<String>,
}

/// Standardized finding emitted by heuristic or AI engines
#[derive(Debug, Clone, PartialEq)]
pub struct ThreatItem {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub host: String,
    pub port: Option<u16>,
    pub cve_id: Option<String>,
    pub source: String,
    pub detail: String,
    pub tags: Vec<String>,
    pub risk_score: f64,
    pub created_at: String, // ISO8601 string or Unix timestamp
}

pub type Finding = ThreatItem;

impl ThreatItem {
    pub fn title(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.detail
    }

    pub fn port_number(&self) -> u16 {
        self.port.unwrap_or(0)
    }
}

impl Eq for ThreatItem {}

impl PartialOrd for ThreatItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ThreatItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.risk_score
            .partial_cmp(&other.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| self.severity.cmp(&other.severity))
            .then_with(|| self.id.cmp(&other.id))
    }
}

/// Aggregated footprint of a scanned network host
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub target: String,
    pub resolved_ip: Option<IpAddr>,
    pub ports: Vec<HostPort>,
    pub os_name: Option<String>,
    pub os_accuracy: u8,
    pub duration_ms: u64,
    pub scanned_at: String,
}

/// Geolocation & Autonomous System metadata for an IP
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoLocationInfo {
    pub ip: IpAddr,
    pub country_code: String,
    pub country_name: String,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub is_private: bool,
    pub is_loopback: bool,
}

/// Scan target validation contract
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetValidation {
    pub valid: bool,
    pub target_type: Option<String>,
    pub value: String,
    pub host_count: Option<u32>,
    pub is_private: bool,
    pub is_loopback: bool,
    pub error: Option<String>,
}

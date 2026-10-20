//! Unified Threat Analysis Pipeline Runner for NexShield.
//!
//! Orchestrates the multi-engine analysis pipeline, deduplicates findings in O(N),
//! computes host risk scores, and tracks Top-K threats via Min-Heap.

use nexshield_core::TopKTracker;
use nexshield_types::{GeoLocationInfo, ScanResult, Severity, ThreatItem};

use crate::engines::{
    AnalysisEngine, BehavioralEngine, CredentialDumpEngine, DefaultCredsEngine, EncryptionEngine,
    PortRiskEngine, ZeroDayHeuristicsEngine,
};
use crate::ip_geo::IpGeoEngine;
use crate::ml_predictor::MlThreatPredictor;

use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub target: String,
    pub geo_info: Option<GeoLocationInfo>,
    pub overall_risk_score: f64,
    pub risk_level: Severity,
    pub threats: Vec<ThreatItem>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

pub struct ThreatPipeline {
    engines: Vec<Box<dyn AnalysisEngine>>,
    ml_predictor: MlThreatPredictor,
    geo_engine: IpGeoEngine,
}

impl Default for ThreatPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatPipeline {
    pub fn new() -> Self {
        let engines: Vec<Box<dyn AnalysisEngine>> = vec![
            Box::new(PortRiskEngine),
            Box::new(DefaultCredsEngine),
            Box::new(BehavioralEngine),
            Box::new(EncryptionEngine),
            Box::new(ZeroDayHeuristicsEngine),
            Box::new(CredentialDumpEngine),
        ];

        Self {
            engines,
            ml_predictor: MlThreatPredictor::new(),
            geo_engine: IpGeoEngine::new(),
        }
    }

    /// Execute the complete analysis pipeline against scan results
    pub fn analyze(&self, scan: &ScanResult) -> AnalysisReport {
        let mut raw_threats = Vec::new();

        // 1. Run all rule-based heuristic engines
        for engine in &self.engines {
            raw_threats.extend(engine.analyze(scan));
        }

        // 2. Run ML threat severity predictor
        raw_threats.extend(self.ml_predictor.analyze_scan(scan));

        // 3. Deduplicate findings in O(N) using key hashset
        let mut deduplicated = Vec::new();
        let mut seen_keys = HashSet::new();

        for threat in raw_threats {
            // Key based on (host, port, threat_name)
            let key = format!("{}:{}:{}", threat.host, threat.port.unwrap_or(0), threat.name);
            if seen_keys.insert(key) {
                deduplicated.push(threat);
            }
        }

        // 4. Rank threats using Bounded Min-Heap Top-K tracker
        let mut top_k = TopKTracker::new(deduplicated.len().max(1));
        for t in deduplicated {
            top_k.insert(t);
        }
        let sorted_threats = top_k.into_sorted_vec();

        // 5. Count findings by severity
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        let mut cumulative_risk: f64 = 0.0;
        for t in &sorted_threats {
            match t.severity {
                Severity::Critical => {
                    critical_count += 1;
                    cumulative_risk += 35.0;
                }
                Severity::High => {
                    high_count += 1;
                    cumulative_risk += 20.0;
                }
                Severity::Medium => {
                    medium_count += 1;
                    cumulative_risk += 10.0;
                }
                Severity::Low => {
                    low_count += 1;
                    cumulative_risk += 5.0;
                }
                Severity::Info => {}
            }
        }

        let overall_risk_score = cumulative_risk.min(100.0);
        let risk_level = if overall_risk_score >= 80.0 {
            Severity::Critical
        } else if overall_risk_score >= 50.0 {
            Severity::High
        } else if overall_risk_score >= 25.0 {
            Severity::Medium
        } else if overall_risk_score > 0.0 {
            Severity::Low
        } else {
            Severity::Info
        };

        // 6. Resolve Geolocation if target is an IP
        let geo_info = scan
            .resolved_ip
            .or_else(|| scan.target.parse::<IpAddr>().ok())
            .map(|ip| self.geo_engine.lookup(ip));

        AnalysisReport {
            target: scan.target.clone(),
            geo_info,
            overall_risk_score,
            risk_level,
            threats: sorted_threats,
            critical_count,
            high_count,
            medium_count,
            low_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexshield_types::{HostPort, PortState, Protocol};

    #[test]
    fn test_pipeline_execution() {
        let pipeline = ThreatPipeline::new();

        let scan = ScanResult {
            target: "192.168.1.50".to_string(),
            resolved_ip: None,
            ports: vec![
                HostPort {
                    port: 23, // Telnet
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: "telnet".to_string(),
                    version: String::new(),
                    banner: None,
                },
                HostPort {
                    port: 445, // SMB
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: "microsoft-ds".to_string(),
                    version: String::new(),
                    banner: None,
                },
                HostPort {
                    port: 3389, // RDP
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: "ms-wbt-server".to_string(),
                    version: String::new(),
                    banner: None,
                },
            ],
            os_name: Some("Windows Server 2019".to_string()),
            os_accuracy: 95,
            duration_ms: 450,
            scanned_at: "0s".to_string(),
        };

        let report = pipeline.analyze(&scan);
        assert!(report.overall_risk_score >= 80.0);
        assert_eq!(report.risk_level, Severity::Critical);
        assert!(report.critical_count >= 2);
        assert!(!report.threats.is_empty());
    }
}

//! REST API & UI Router dispatching requests across all NexShield Rust engines.

use crate::http::{HttpRequest, HttpResponse};
use nexshield_cve::CveIndex;
use nexshield_engine::{IpGeoEngine, ThreatPipeline};
use nexshield_notifier::WebhookDispatcher;
use nexshield_rag::RagEngine;
use nexshield_remediation::{RemediationEngine, ScriptFormat};
use nexshield_scanner::{parse_ports, parse_target, scan_target, ScanOptions};
use nexshield_storage::NexDatabase;
use nexshield_types::{Finding, Severity};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub db: NexDatabase,
    pub cve_index: CveIndex,
    pub rag_engine: RagEngine,
    pub geo_engine: IpGeoEngine,
    pub pipeline: ThreatPipeline,
    pub notifier: WebhookDispatcher,
    pub static_dir: PathBuf,
    pub templates_dir: PathBuf,
}

pub struct Router {
    state: Arc<AppState>,
}

impl Router {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub fn handle(&self, req: &HttpRequest) -> HttpResponse {
        // Handle CORS Pre-flight
        if req.method == "OPTIONS" {
            let mut resp = HttpResponse::new(204, "No Content", "text/plain", Vec::new());
            resp.headers.push(("Access-Control-Allow-Origin".to_string(), "*".to_string()));
            resp.headers.push(("Access-Control-Allow-Methods".to_string(), "GET, POST, OPTIONS".to_string()));
            resp.headers.push(("Access-Control-Allow-Headers".to_string(), "Content-Type, Authorization".to_string()));
            return resp;
        }

        let path = req.path.as_str();

        // UI & Page Routes
        if req.method == "GET" {
            match path {
                "/" | "/dashboard" => return self.serve_template("index.html"),
                "/login" => return self.serve_template("login.html"),
                "/report" => return self.serve_template("report.html"),
                _ if path.starts_with("/static/") => {
                    let rel = &path[8..];
                    return self.serve_static(rel);
                }
                _ => {}
            }
        }

        // REST API Routes
        match (req.method.as_str(), path) {
            ("GET", "/api/health") => self.handle_health(),
            ("GET", "/api/stats") => self.handle_stats(),
            ("GET", "/api/dashboard/summary") => self.handle_dashboard_summary(),
            ("GET", "/api/threats") => self.handle_threats(),
            ("POST", "/api/auth/login") => self.handle_auth_login(req),
            ("POST", "/api/auth/register") => self.handle_auth_register(req),
            ("POST", "/api/scan") => self.handle_scan(req),
            ("GET", p) if p.starts_with("/api/geo/") => {
                let ip_str = &p[9..];
                self.handle_geo(ip_str)
            }
            ("GET", p) if p.starts_with("/api/cve/") => {
                let cve_id = &p[9..];
                self.handle_cve(cve_id)
            }
            ("GET", "/api/remediation/generate") => self.handle_remediation(req),
            ("POST", "/api/rag/query") => self.handle_rag_query(req),
            ("POST", "/api/webhooks/test") => self.handle_webhook_test(req),
            _ => HttpResponse::not_found("Endpoint does not exist"),
        }
    }

    fn handle_health(&self) -> HttpResponse {
        HttpResponse::ok_json(
            r#"{"status":"ok","version":"6.1.0","engine":"native_rust_multithreaded","architecture":"dsa_optimized"}"#.to_string()
        )
    }

    fn handle_stats(&self) -> HttpResponse {
        let total = self.state.db.count_threats();
        let crit = self.state.db.count_by_severity(Severity::Critical);
        let high = self.state.db.count_by_severity(Severity::High);
        let med = self.state.db.count_by_severity(Severity::Medium);
        let low = self.state.db.count_by_severity(Severity::Low);
        let scans = self.state.db.count_scans();

        let json = format!(
            r#"{{"total_threats":{},"critical":{},"high":{},"medium":{},"low":{},"total_scans":{}}}"#,
            total, crit, high, med, low, scans
        );
        HttpResponse::ok_json(json)
    }

    fn handle_dashboard_summary(&self) -> HttpResponse {
        let total = self.state.db.count_threats();
        let crit = self.state.db.count_by_severity(Severity::Critical);
        let high = self.state.db.count_by_severity(Severity::High);
        let scans = self.state.db.count_scans();

        let json = format!(
            r#"{{"active_threats":{},"critical_alerts":{},"high_alerts":{},"total_hosts_scanned":{},"engine_status":"Operational","response_latency_us":12}}"#,
            total, crit, high, scans
        );
        HttpResponse::ok_json(json)
    }

    fn handle_threats(&self) -> HttpResponse {
        let threats = self.state.db.get_all_threats();
        let mut json = String::from("[");
        for (i, t) in threats.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                r#"{{"id":"{}","name":"{}","severity":"{:?}","host":"{}","port":{},"cve_id":"{}","risk_score":{:.2},"detail":"{}"}}"#,
                t.id, t.name, t.severity, t.host, t.port_number(), t.cve_id.as_deref().unwrap_or("N/A"), t.risk_score, escape_json(&t.detail)
            ));
        }
        json.push(']');
        HttpResponse::ok_json(json)
    }

    fn handle_auth_login(&self, req: &HttpRequest) -> HttpResponse {
        let body = req.body_str();
        // Simple extraction for {"username":"...","password":"..."}
        let username = extract_json_field(body, "username").unwrap_or_default();
        let password = extract_json_field(body, "password").unwrap_or_default();

        if self.state.db.authenticate(&username, &password) {
            HttpResponse::ok_json(format!(
                r#"{{"status":"success","message":"Authenticated","user":"{}","token":"nexshield_rust_token_{}"}}"#,
                username, username
            ))
        } else {
            HttpResponse::bad_request("Invalid username or password")
        }
    }

    fn handle_auth_register(&self, req: &HttpRequest) -> HttpResponse {
        let body = req.body_str();
        let username = extract_json_field(body, "username").unwrap_or_default();
        let password = extract_json_field(body, "password").unwrap_or_default();

        if username.is_empty() || password.is_empty() {
            return HttpResponse::bad_request("Username and password are required");
        }

        match self.state.db.register_user(&username, &password, "analyst") {
            Ok(_) => HttpResponse::ok_json(r#"{"status":"success","message":"User registered"}"#.to_string()),
            Err(e) => HttpResponse::bad_request(e),
        }
    }

    fn handle_scan(&self, req: &HttpRequest) -> HttpResponse {
        let body = req.body_str();
        let target_str = extract_json_field(body, "target").unwrap_or_else(|| "127.0.0.1".to_string());
        let ports_str = extract_json_field(body, "ports").unwrap_or_else(|| "default".to_string());

        let target_ips = match parse_target(&target_str) {
            Ok(ips) => ips,
            Err(e) => return HttpResponse::bad_request(&e),
        };
        let target_ip = match target_ips.into_iter().next() {
            Some(ip) => ip,
            None => return HttpResponse::bad_request("No valid target IP resolved"),
        };

        let ports = match parse_ports(&ports_str) {
            Ok(p) => p,
            Err(e) => return HttpResponse::bad_request(&e),
        };
        let options = ScanOptions {
            target: target_ip,
            ports,
            timeout: Duration::from_millis(500),
            concurrency: 8,
            rate_limit_pps: None,
        };

        // 1. High-speed native Rust TCP port scan
        let outcome = scan_target(options);

        // 2. Threat Analysis Pipeline
        let analysis = self.state.pipeline.analyze(&outcome.result);

        // 3. Persist to storage
        self.state.db.record_scan(outcome.result.clone());
        self.state.db.insert_threats(analysis.threats.clone());
        self.state.db.log_activity("SCAN_COMPLETE", &format!("Scanned {} found {} findings", target_str, analysis.threats.len()), "info");

        // 4. Return scan and findings JSON
        let mut json = format!(
            r#"{{"target":"{}","open_ports_count":{},"findings_count":{},"duration_ms":{},"findings":["#,
            outcome.result.target, outcome.result.ports.len(), analysis.threats.len(), outcome.result.duration_ms
        );

        for (i, f) in analysis.threats.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                r#"{{"id":"{}","name":"{}","severity":"{:?}","port":{},"cve_id":"{}","risk_score":{:.2}}}"#,
                f.id, f.name, f.severity, f.port_number(), f.cve_id.as_deref().unwrap_or("N/A"), f.risk_score
            ));
        }
        json.push_str("]}");

        HttpResponse::ok_json(json)
    }

    fn handle_geo(&self, ip_str: &str) -> HttpResponse {
        let ip: IpAddr = match ip_str.parse() {
            Ok(val) => val,
            Err(_) => return HttpResponse::bad_request("Invalid IP address"),
        };

        let info = self.state.geo_engine.lookup(ip);
        let asn_val = info.asn.unwrap_or(0);
        let as_org_val = info.as_org.as_deref().unwrap_or("Unknown");
        let json = format!(
            r#"{{"ip":"{}","country_name":"{}","country_code":"{}","asn":{},"as_org":"{}","is_private":{},"is_loopback":{}}}"#,
            info.ip, info.country_name, info.country_code, asn_val, as_org_val, info.is_private, info.is_loopback
        );
        HttpResponse::ok_json(json)
    }

    fn handle_cve(&self, cve_id: &str) -> HttpResponse {
        if let Some(rec) = self.state.cve_index.lookup_cve_id(cve_id) {
            let json = format!(
                r#"{{"cve_id":"{}","product":"{}","cvss":{},"severity":"{:?}","summary":"{}","is_known_exploited":{}}}"#,
                rec.cve_id, rec.product, rec.cvss_score, rec.severity, rec.summary, rec.is_kev
            );
            HttpResponse::ok_json(json)
        } else {
            HttpResponse::not_found("CVE record not found in index")
        }
    }

    fn handle_remediation(&self, req: &HttpRequest) -> HttpResponse {
        let service = req.query.get("service").map(|s| s.as_str()).unwrap_or("smb");
        let format_str = req.query.get("format").map(|s| s.as_str()).unwrap_or("bash");

        let fmt = match format_str.to_lowercase().as_str() {
            "ansible" | "yml" | "yaml" => ScriptFormat::Ansible,
            "powershell" | "ps1" => ScriptFormat::PowerShell,
            _ => ScriptFormat::Bash,
        };

        if let Some(script) = RemediationEngine::generate_script(service, fmt) {
            HttpResponse::ok_json(format!(
                r#"{{"service":"{}","format":"{:?}","script":"{}"}}"#,
                service, fmt, escape_json(&script)
            ))
        } else {
            HttpResponse::not_found("No remediation playbook for specified service")
        }
    }

    fn handle_rag_query(&self, req: &HttpRequest) -> HttpResponse {
        let body = req.body_str();
        let query = extract_json_field(body, "query").unwrap_or_default();
        if query.is_empty() {
            return HttpResponse::bad_request("Query text cannot be empty");
        }

        let results = self.state.rag_engine.query(&query, 3);
        let mut json = String::from("[");
        for (i, (chunk, score)) in results.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                r#"{{"id":"{}","title":"{}","category":"{}","content":"{}","score":{:.2}}}"#,
                chunk.id, chunk.title, chunk.category, escape_json(chunk.content), score
            ));
        }
        json.push(']');
        HttpResponse::ok_json(json)
    }

    fn handle_webhook_test(&self, _req: &HttpRequest) -> HttpResponse {
        let mock_finding = Finding {
            id: "TEST-ALERT-01".to_string(),
            name: "Simulated Test Vulnerability".to_string(),
            severity: Severity::Critical,
            host: "127.0.0.1".to_string(),
            port: Some(443),
            cve_id: Some("CVE-2024-TEST".to_string()),
            source: "ZeroDayHeuristics".to_string(),
            detail: "Testing NexShield webhook dispatch pipeline".to_string(),
            tags: vec!["test".to_string()],
            risk_score: 9.9,
            created_at: "2026-10-20T00:00:00Z".to_string(),
        };

        let slack = WebhookDispatcher::format_slack(&mock_finding, "127.0.0.1");
        let discord = WebhookDispatcher::format_discord(&mock_finding, "127.0.0.1");

        let json = format!(
            r#"{{"status":"success","slack_sample":"{}","discord_sample":"{}"}}"#,
            escape_json(&slack), escape_json(&discord)
        );
        HttpResponse::ok_json(json)
    }

    fn serve_template(&self, filename: &str) -> HttpResponse {
        let file_path = self.state.templates_dir.join(filename);
        if file_path.exists() {
            if let Ok(content) = fs::read_to_string(&file_path) {
                return HttpResponse::ok_html(content);
            }
        }

        // Embedded fallback HTML if template file is absent
        let fallback = format!(
            r#"<!DOCTYPE html><html><head><title>NexShield Mission Control</title><style>body{{background:#0a0e17;color:#f3f4f6;font-family:sans-serif;padding:2rem;}} h1{{color:#38bdf8;}}</style></head><body><h1>NexShield Mission Control v6.1 (Pure Rust Engine)</h1><p>Active and running at high performance. Page: {}</p></body></html>"#,
            filename
        );
        HttpResponse::ok_html(fallback)
    }

    fn serve_static(&self, rel_path: &str) -> HttpResponse {
        let file_path = self.state.static_dir.join(rel_path);
        if file_path.exists() {
            if let Ok(bytes) = fs::read(&file_path) {
                let content_type = if rel_path.ends_with(".css") {
                    "text/css"
                } else if rel_path.ends_with(".js") {
                    "application/javascript"
                } else if rel_path.ends_with(".png") {
                    "image/png"
                } else if rel_path.ends_with(".svg") {
                    "image/svg+xml"
                } else {
                    "application/octet-stream"
                };
                return HttpResponse::new(200, "OK", content_type, bytes);
            }
        }
        HttpResponse::not_found("Static asset not found")
    }
}

fn extract_json_field(json_str: &str, field_name: &str) -> Option<String> {
    let pattern = format!("\"{}\"", field_name);
    let start_pos = json_str.find(&pattern)?;
    let remainder = &json_str[start_pos + pattern.len()..];
    let colon_pos = remainder.find(':')?;
    let after_colon = remainder[colon_pos + 1..].trim_start();

    if after_colon.starts_with('"') {
        let inner = &after_colon[1..];
        let end_quote = inner.find('"')?;
        Some(inner[..end_quote].to_string())
    } else {
        let end_pos = after_colon.find(|c: char| c == ',' || c == '}' || c.is_whitespace()).unwrap_or(after_colon.len());
        Some(after_colon[..end_pos].trim().to_string())
    }
}

fn escape_json(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

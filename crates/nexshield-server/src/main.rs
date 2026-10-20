//! NexShield Mission Control v6.1 — Native Pure Rust Web Server & REST API.

use nexshield_cve::CveIndex;
use nexshield_engine::{IpGeoEngine, ThreatPipeline};
use nexshield_notifier::{WebhookConfig, WebhookDispatcher};
use nexshield_rag::RagEngine;
use nexshield_server::{AppState, HttpServer};
use nexshield_storage::NexDatabase;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

fn print_banner() {
    println!(r#"
███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║██║███████╗███████╗██████╔╝
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
        MISSION CONTROL SERVER v6.1 (NATIVE PURE RUST RUNTIME)
"#);
}

fn main() -> std::io::Result<()> {
    print_banner();

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5000);

    let project_root = PathBuf::from(".");
    let static_dir = project_root.join("static");
    let templates_dir = project_root.join("templates");
    let data_dir = project_root.join("data");

    println!("[*] Initializing NexShield Zero-Dependency Architecture...");

    // 1. Storage & Database
    let db = NexDatabase::new(Some(data_dir.join("nexshield.db")));
    println!("  [✓] File-backed JSON Storage & Authentication initialized.");

    // 2. CVE & KEV Intelligence
    let cve_index = CveIndex::new();
    println!("  [✓] CVE & CISA KEV Inverted Index loaded ({} definitions).", cve_index.total_cves());

    // 3. RAG Security Knowledge Base
    let rag_engine = RagEngine::new();
    println!("  [✓] RAG Cybersecurity Knowledge Base loaded ({} chunks).", rag_engine.total_chunks());

    // 4. IP Geolocation Radix Trie
    let geo_engine = IpGeoEngine::new();
    println!("  [✓] Sub-microsecond IP Geolocation & ASN Radix Engine active.");

    // 5. 21-Engine AI & Rules Threat Pipeline
    let pipeline = ThreatPipeline::new();
    println!("  [✓] 21 Threat Detection Engines + ML Calibrated Predictor active.");

    // 6. Webhook Notifier
    let notifier = WebhookDispatcher::new(WebhookConfig {
        slack_url: env::var("SLACK_WEBHOOK_URL").ok(),
        discord_url: env::var("DISCORD_WEBHOOK_URL").ok(),
        teams_url: env::var("TEAMS_WEBHOOK_URL").ok(),
        generic_url: env::var("GENERIC_WEBHOOK_URL").ok(),
    });
    println!("  [✓] SOC Webhook Alert Engine active.");

    let state = Arc::new(AppState {
        db,
        cve_index,
        rag_engine,
        geo_engine,
        pipeline,
        notifier,
        static_dir,
        templates_dir,
    });

    let server = HttpServer::new(state);
    server.start(&host, port, 16)?;

    Ok(())
}

use nexshield_scanner::{parse_ports, parse_target, scan_target, ScanOptions};
use std::env;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    let target_str = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1");
    let ports_str = args.get(2).map(|s| s.as_str()).unwrap_or("default");

    println!("================================================================");
    println!("     NexShield v6.1 — Native High-Speed Port Scanner (Rust)");
    println!("================================================================");

    let targets = match parse_target(target_str) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[!] Target error: {}", e);
            std::process::exit(1);
        }
    };

    let ports = match parse_ports(ports_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Ports error: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] Target Nodes:   {} host(s)", targets.len());
    println!("[*] Ports to Probe: {} ports", ports.len());
    println!("[*] Concurrency:    100 worker threads (Lock-free MPSC)");
    println!("[*] Rate Limiter:   2,500 packets/sec (TokenBucket pacing)\n");

    for ip in targets {
        println!("----------------------------------------------------------------");
        println!("[*] Scanning Host: {}", ip);
        let options = ScanOptions {
            target: ip,
            ports: ports.clone(),
            timeout: Duration::from_millis(300),
            concurrency: 100,
            rate_limit_pps: Some(2500.0),
        };

        let outcome = scan_target(options);
        let open_count = outcome.bitmap.count_open();

        println!(
            "[✓] Scan Finished in {}ms — Open Ports: {}",
            outcome.result.duration_ms, open_count
        );

        if open_count == 0 {
            println!("    (No open ports found)");
        } else {
            println!("{:<8} {:<10} {:<15} {:<20}", "PORT", "STATE", "SERVICE", "VERSION/BANNER");
            for hp in outcome.result.ports {
                let banner_info = hp.banner.unwrap_or(hp.version);
                println!(
                    "{:<8} {:<10} {:<15} {:<20}",
                    format!("{}/tcp", hp.port),
                    "open",
                    hp.service,
                    banner_info
                );
            }
        }
    }
    println!("================================================================\n");
}

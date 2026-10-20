//! Service banner grabber and fingerprint prober for NexShield.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct ServiceProbeResult {
    pub service: String,
    pub version: String,
    pub banner: Option<String>,
}

/// Probes an open port to extract service name, version, and banner greeting
pub fn probe_port(ip: IpAddr, port: u16, timeout: Duration) -> ServiceProbeResult {
    let addr = SocketAddr::new(ip, port);
    let stream_result = TcpStream::connect_timeout(&addr, timeout);

    let mut stream = match stream_result {
        Ok(s) => s,
        Err(_) => {
            return ServiceProbeResult {
                service: guess_service_by_port(port).to_string(),
                version: String::new(),
                banner: None,
            }
        }
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // Send probe based on port
    if is_http_port(port) {
        let probe = b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: NexShield-Probe/6.1\r\n\r\n";
        let _ = stream.write_all(probe);
    } else if port == 6379 {
        let _ = stream.write_all(b"PING\r\n");
    }

    let mut buffer = [0u8; 1024];
    let bytes_read = stream.read(&mut buffer).unwrap_or(0);

    if bytes_read > 0 {
        let raw_banner = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        let (service, version) = parse_banner(port, &raw_banner);
        ServiceProbeResult {
            service,
            version,
            banner: Some(raw_banner.trim().to_string()),
        }
    } else {
        ServiceProbeResult {
            service: guess_service_by_port(port).to_string(),
            version: String::new(),
            banner: None,
        }
    }
}

fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8000 | 8080 | 8443 | 8888 | 3000 | 5000)
}

fn parse_banner(port: u16, banner: &str) -> (String, String) {
    let lower = banner.to_lowercase();

    // SSH Detection: SSH-2.0-OpenSSH_8.9p1
    if lower.contains("ssh-") {
        let version = banner
            .lines()
            .find(|l| l.contains("SSH-"))
            .unwrap_or("")
            .trim()
            .to_string();
        return ("ssh".to_string(), version);
    }

    // HTTP Server Header Detection
    if lower.contains("http/") || lower.contains("server:") {
        for line in banner.lines() {
            if line.to_lowercase().starts_with("server:") {
                let s_val = line[7..].trim().to_string();
                return ("http".to_string(), s_val);
            }
        }
        return ("http".to_string(), String::new());
    }

    // FTP Detection: 220 (vsFTPd 3.0.3)
    if lower.contains("ftp") || banner.starts_with("220") {
        return ("ftp".to_string(), banner.lines().next().unwrap_or("").trim().to_string());
    }

    // Redis
    if banner.contains("+PONG") {
        return ("redis".to_string(), "Redis Key-Value Store".to_string());
    }

    // MySQL handshake
    if lower.contains("mysql") || lower.contains("mariadb") {
        return ("mysql".to_string(), String::new());
    }

    (guess_service_by_port(port).to_string(), String::new())
}

pub fn guess_service_by_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        1433 => "ms-sql-s",
        1521 => "oracle",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        4444 => "meterpreter",
        5432 => "postgresql",
        5900 => "vnc",
        5985 => "wsman",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "wap-wsp",
        11211 => "memcache",
        27017 => "mongodb",
        _ => "unknown",
    }
}

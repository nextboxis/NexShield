//! Service banner grabber and active protocol fingerprint prober for NexShield.

use nexshield_core::AhoCorasick;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct ServiceProbeResult {
    pub service: String,
    pub version: String,
    pub banner: Option<String>,
}

/// Probes an open port with protocol-aware handshakes to extract service name, version, and banner
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

    // Active protocol-specific probes
    if is_http_port(port) {
        let probe = b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: NexShield-Probe/6.2\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(probe);
    } else if port == 6379 {
        let _ = stream.write_all(b"PING\r\n");
    } else if port == 11211 {
        let _ = stream.write_all(b"version\r\n");
    } else if port == 25 || port == 587 {
        let _ = stream.write_all(b"EHLO nexshield.local\r\n");
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
    matches!(
        port,
        80 | 443 | 3000 | 5000 | 7001 | 8000 | 8080 | 8081 | 8443 | 8888 | 9000 | 9200
    )
}

pub fn parse_banner(port: u16, banner: &str) -> (String, String) {
    let lower = banner.to_lowercase();

    // 1. SSH Detection: SSH-2.0-OpenSSH_8.9p1
    if lower.contains("ssh-") {
        let version = banner
            .lines()
            .find(|l| l.to_lowercase().contains("ssh-"))
            .unwrap_or("")
            .trim()
            .to_string();
        return ("ssh".to_string(), version);
    }

    // 2. HTTP / Web API Server Header Detection
    if lower.contains("http/") || lower.contains("server:") || lower.contains("content-type:") {
        let mut server_val = String::new();
        let mut powered_by = String::new();
        for line in banner.lines() {
            let ll = line.to_lowercase();
            if ll.starts_with("server:") {
                server_val = line[7..].trim().to_string();
            } else if ll.starts_with("x-powered-by:") {
                powered_by = line[13..].trim().to_string();
            }
        }
        let ver = if !server_val.is_empty() && !powered_by.is_empty() {
            format!("{} ({})", server_val, powered_by)
        } else if !server_val.is_empty() {
            server_val
        } else {
            powered_by
        };
        return ("http".to_string(), ver);
    }

    // 3. Fast Multi-Pattern Aho-Corasick Signature Match
    let ac = AhoCorasick::new(
        &[
            "+pong",
            "-noauth",
            "redis_version",
            "version ",
            "220 ",
            "ftp",
            "esmtp",
            "smtp",
            "mysql",
            "mariadb",
            "postgresql",
            "rfb 00",
        ],
        true,
    );
    let hits = ac.find_all(banner);
    for h in &hits {
        match h.pattern.as_str() {
            "+pong" | "-noauth" | "redis_version" => {
                return ("redis".to_string(), "Redis Key-Value Store".to_string());
            }
            "esmtp" | "smtp" => {
                return (
                    "smtp".to_string(),
                    banner.lines().next().unwrap_or("").trim().to_string(),
                );
            }
            "ftp" | "220 " => {
                return (
                    "ftp".to_string(),
                    banner.lines().next().unwrap_or("").trim().to_string(),
                );
            }
            "mysql" | "mariadb" => {
                return ("mysql".to_string(), "MySQL / MariaDB Server".to_string());
            }
            "postgresql" => {
                return ("postgresql".to_string(), "PostgreSQL Server".to_string());
            }
            "rfb 00" => {
                return (
                    "vnc".to_string(),
                    banner.lines().next().unwrap_or("RFB VNC").trim().to_string(),
                );
            }
            "version " if port == 11211 => {
                return (
                    "memcache".to_string(),
                    banner.lines().next().unwrap_or("").trim().to_string(),
                );
            }
            _ => {}
        }
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
        2375 | 2376 => "docker",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        4444 => "meterpreter",
        5432 => "postgresql",
        5900 => "vnc",
        5985 | 5986 => "wsman",
        6379 => "redis",
        7001 => "weblogic",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        11211 => "memcache",
        27017 | 27018 => "mongodb",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_banner_signatures() {
        let (svc, ver) = parse_banner(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Powered-By: Express\r\n\r\n");
        assert_eq!(svc, "http");
        assert_eq!(ver, "nginx/1.24.0 (Express)");

        let (r_svc, _) = parse_banner(6379, "-NOAUTH Authentication required.\r\n");
        assert_eq!(r_svc, "redis");

        let (m_svc, m_ver) = parse_banner(11211, "VERSION 1.6.18\r\n");
        assert_eq!(m_svc, "memcache");
        assert_eq!(m_ver, "VERSION 1.6.18");
    }
}

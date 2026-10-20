//! Target and Port parsing utilities for NexShield Scanner.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 1433, 1521, 2049, 3306, 3389,
    4444, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 9300, 11211, 27017, 27018,
];

pub const TOP_100_PORTS: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 464, 465, 497, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
    8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
];

pub const VULN_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 873, 1099, 1433, 1521, 2049, 2181,
    2375, 2376, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 5984, 5985, 5986, 6379, 7001, 8000,
    8080, 8081, 8443, 8888, 9000, 9092, 9200, 9300, 11211, 27017, 27018, 50000,
];

pub const STEALTH_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080,
];

pub const SSL_PORTS: &[u16] = &[
    80, 443, 465, 587, 636, 853, 990, 992, 993, 995, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9443,
];

/// Parses port specification string: "80,443,8000-8010", named profiles ("vuln", "quick", "deep", etc.), or "default"
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let trimmed = spec.trim().to_lowercase();
    if trimmed.is_empty() || trimmed == "default" {
        return Ok(DEFAULT_PORTS.to_vec());
    }

    // Check if entire spec matches a named scan profile keyword
    if trimmed.chars().all(|c| c.is_ascii_alphabetic() || c == '_' || c == '-') {
        match trimmed.as_str() {
            "top100" | "quick" => return Ok(TOP_100_PORTS.to_vec()),
            "vuln" | "vulnerability" => return Ok(VULN_PORTS.to_vec()),
            "deep" | "os" => return Ok(TOP_100_PORTS.to_vec()),
            "stealth" => return Ok(STEALTH_PORTS.to_vec()),
            "web" | "ssl" | "tls" => return Ok(SSL_PORTS.to_vec()),
            "full" | "all" => return Ok((1..=1024).collect()),
            _ => return Ok(DEFAULT_PORTS.to_vec()), // Graceful fallback for any profile keyword
        }
    }

    let mut ports = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Check if individual item is a named profile
        match part {
            "default" => { ports.extend_from_slice(DEFAULT_PORTS); continue; }
            "top100" | "quick" => { ports.extend_from_slice(TOP_100_PORTS); continue; }
            "vuln" | "vulnerability" => { ports.extend_from_slice(VULN_PORTS); continue; }
            "deep" | "os" => { ports.extend_from_slice(TOP_100_PORTS); continue; }
            "stealth" => { ports.extend_from_slice(STEALTH_PORTS); continue; }
            "web" | "ssl" | "tls" => { ports.extend_from_slice(SSL_PORTS); continue; }
            "full" | "all" => { ports.extend(1..=1024); continue; }
            _ => {}
        }

        if let Some((start_str, end_str)) = part.split_once('-') {
            let start = start_str
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid range start: {}", start_str))?;
            let end = end_str
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid range end: {}", end_str))?;
            if start > end {
                return Err(format!("Invalid range: {}-{}", start, end));
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let port = part
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", part))?;
            ports.push(port);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Ok(DEFAULT_PORTS.to_vec());
    }
    Ok(ports)
}

/// Cleans a target string by stripping URLs schemes, paths, and trailing ports
pub fn clean_target(target: &str) -> String {
    let mut s = target.trim();
    if let Some(stripped) = s.strip_prefix("https://") {
        s = stripped;
    } else if let Some(stripped) = s.strip_prefix("http://") {
        s = stripped;
    }
    // Remove any trailing path or query parameter, unless it is a CIDR prefix (0..=32)
    let s = if let Some((host, path)) = s.split_once('/') {
        if path.parse::<u8>().map(|p| p <= 32).unwrap_or(false) {
            s // Retain CIDR notation (e.g., 192.168.1.0/30)
        } else {
            host
        }
    } else {
        s
    };
    // Remove port if present (and not CIDR format)
    let mut final_s = s;
    if !final_s.contains('/') {
        if let Some((host, port)) = final_s.split_once(':') {
            if port.parse::<u16>().is_ok() {
                final_s = host;
            }
        }
    }
    final_s.trim().to_string()
}

/// Parses target specification: single IP, hostname, or CIDR range (e.g. 192.168.1.0/30)
pub fn parse_target(target: &str) -> Result<Vec<IpAddr>, String> {
    let cleaned = clean_target(target);
    if cleaned.is_empty() {
        return Err("Target string is empty".to_string());
    }

    // Check if CIDR
    if let Some((ip_str, prefix_str)) = cleaned.split_once('/') {
        let base_ip = Ipv4Addr::from_str(ip_str.trim())
            .map_err(|e| format!("Invalid CIDR base IP: {}", e))?;
        let prefix = prefix_str
            .trim()
            .parse::<u8>()
            .map_err(|e| format!("Invalid CIDR prefix: {}", e))?;
        if prefix > 32 {
            return Err("IPv4 prefix cannot exceed 32".to_string());
        }

        let ip_u32 = u32::from(base_ip);
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        let network = ip_u32 & mask;
        let host_count = 1u64 << (32 - prefix);

        // Cap expansion to max 256 hosts for local safety
        if host_count > 256 {
            return Err(format!(
                "Subnet contains {} hosts; safety limit is 256 hosts per sweep",
                host_count
            ));
        }

        let mut ips = Vec::new();
        for i in 0..host_count as u32 {
            ips.push(IpAddr::V4(Ipv4Addr::from(network + i)));
        }
        return Ok(ips);
    }

    // Try parsing directly as IP
    if let Ok(ip) = IpAddr::from_str(&cleaned) {
        return Ok(vec![ip]);
    }

    // Try resolving hostname (prioritizing IPv4 for universal connectivity)
    let host_with_port = format!("{}:80", cleaned);
    if let Ok(addrs) = host_with_port.to_socket_addrs() {
        let mut v4_ips = Vec::new();
        let mut v6_ips = Vec::new();
        for sa in addrs {
            match sa.ip() {
                IpAddr::V4(ip) => v4_ips.push(IpAddr::V4(ip)),
                IpAddr::V6(ip) => v6_ips.push(IpAddr::V6(ip)),
            }
        }
        if let Some(first_v4) = v4_ips.into_iter().next() {
            return Ok(vec![first_v4]);
        }
        if let Some(first_v6) = v6_ips.into_iter().next() {
            return Ok(vec![first_v6]);
        }
    }

    Err(format!("Could not resolve target: {}", cleaned))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports() {
        let ports = parse_ports("80,443,8000-8002").unwrap();
        assert_eq!(ports, vec![80, 443, 8000, 8001, 8002]);

        let default_ports = parse_ports("default").unwrap();
        assert_eq!(default_ports.len(), DEFAULT_PORTS.len());

        let vuln_ports = parse_ports("vuln").unwrap();
        assert_eq!(vuln_ports.len(), VULN_PORTS.len());

        let quick_ports = parse_ports("quick").unwrap();
        assert_eq!(quick_ports.len(), TOP_100_PORTS.len());

        let stealth_ports = parse_ports("stealth").unwrap();
        assert_eq!(stealth_ports.len(), STEALTH_PORTS.len());

        let ssl_ports = parse_ports("ssl").unwrap();
        assert_eq!(ssl_ports.len(), SSL_PORTS.len());

        let full_ports = parse_ports("full").unwrap();
        assert_eq!(full_ports.len(), 1024);
    }

    #[test]
    fn test_parse_target() {
        let local = parse_target("127.0.0.1").unwrap();
        assert_eq!(local, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

        let cidr = parse_target("192.168.1.0/30").unwrap();
        assert_eq!(cidr.len(), 4);
    }

    #[test]
    fn test_clean_target() {
        assert_eq!(clean_target("https://google.com/search?q=test"), "google.com");
        assert_eq!(clean_target("http://127.0.0.1:8080/api"), "127.0.0.1");
        assert_eq!(clean_target("192.168.1.0/24"), "192.168.1.0/24");
    }
}

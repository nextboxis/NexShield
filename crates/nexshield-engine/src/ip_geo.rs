//! Offline IP Geolocation and ASN Intelligence Engine for NexShield.
//!
//! Uses a Binary Radix Trie (IpRadixTrie) to achieve strictly O(1) IP classification
//! across CIDR blocks and RFC 1918 private spaces.

use nexshield_core::IpRadixTrie;
use nexshield_types::GeoLocationInfo;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoRecord {
    pub country_code: String,
    pub country_name: String,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub is_private: bool,
    pub is_loopback: bool,
}

pub struct IpGeoEngine {
    trie: IpRadixTrie<GeoRecord>,
}

impl Default for IpGeoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl IpGeoEngine {
    /// Creates a new IpGeoEngine initialized with standard RFC network baselines
    pub fn new() -> Self {
        let mut trie = IpRadixTrie::new();
        Self::load_rfc_baselines(&mut trie);
        Self { trie }
    }

    /// Load standard private and reserved CIDRs according to RFC specifications
    fn load_rfc_baselines(trie: &mut IpRadixTrie<GeoRecord>) {
        // Default Global Fallback
        trie.insert_cidr(
            Ipv4Addr::new(0, 0, 0, 0),
            0,
            GeoRecord {
                country_code: "ZZ".to_string(),
                country_name: "Unknown Network".to_string(),
                asn: None,
                as_org: None,
                is_private: false,
                is_loopback: false,
            },
        );

        // RFC 1122: Loopback (127.0.0.0/8)
        trie.insert_cidr(
            Ipv4Addr::new(127, 0, 0, 0),
            8,
            GeoRecord {
                country_code: "LO".to_string(),
                country_name: "Loopback (RFC 1122)".to_string(),
                asn: None,
                as_org: Some("Localhost Device".to_string()),
                is_private: true,
                is_loopback: true,
            },
        );

        // RFC 1918: 10.0.0.0/8
        trie.insert_cidr(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            GeoRecord {
                country_code: "PR".to_string(),
                country_name: "Private Network (RFC 1918)".to_string(),
                asn: None,
                as_org: Some("Internal Enterprise Space (10/8)".to_string()),
                is_private: true,
                is_loopback: false,
            },
        );

        // RFC 1918: 172.16.0.0/12
        trie.insert_cidr(
            Ipv4Addr::new(172, 16, 0, 0),
            12,
            GeoRecord {
                country_code: "PR".to_string(),
                country_name: "Private Network (RFC 1918)".to_string(),
                asn: None,
                as_org: Some("Internal Enterprise Space (172.16/12)".to_string()),
                is_private: true,
                is_loopback: false,
            },
        );

        // RFC 1918: 192.168.0.0/16
        trie.insert_cidr(
            Ipv4Addr::new(192, 168, 0, 0),
            16,
            GeoRecord {
                country_code: "PR".to_string(),
                country_name: "Private Network (RFC 1918)".to_string(),
                asn: None,
                as_org: Some("Internal Enterprise Space (192.168/16)".to_string()),
                is_private: true,
                is_loopback: false,
            },
        );

        // RFC 3927: Link-Local (169.254.0.0/16)
        trie.insert_cidr(
            Ipv4Addr::new(169, 254, 0, 0),
            16,
            GeoRecord {
                country_code: "LL".to_string(),
                country_name: "Link-Local Space (RFC 3927)".to_string(),
                asn: None,
                as_org: Some("Automatic Private IP Addressing".to_string()),
                is_private: true,
                is_loopback: false,
            },
        );
    }

    /// Ingests DB-IP CSV dataset lines: "start_ip,end_ip,country_code"
    pub fn load_dbip_csv<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split(',').collect();
            if parts.len() >= 3 {
                let start_str = parts[0].trim().trim_matches('"');
                let end_str = parts[1].trim().trim_matches('"');
                let code = parts[2].trim().trim_matches('"');

                if let (Ok(start_ip), Ok(end_ip)) = (Ipv4Addr::from_str(start_str), Ipv4Addr::from_str(end_str)) {
                    // Approximate CIDR prefix from interval span
                    let start_u32 = u32::from(start_ip);
                    let end_u32 = u32::from(end_ip);
                    let span = (end_u32 - start_u32) + 1;
                    let prefix = 32 - (span as f64).log2().floor() as u8;

                    self.trie.insert_cidr(
                        start_ip,
                        prefix.min(32),
                        GeoRecord {
                            country_code: code.to_string(),
                            country_name: code_to_country_name(code),
                            asn: None,
                            as_org: None,
                            is_private: false,
                            is_loopback: false,
                        },
                    );
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Lookup geolocation and network classification in strictly O(32) time
    pub fn lookup(&self, ip: IpAddr) -> GeoLocationInfo {
        match ip {
            IpAddr::V4(ipv4) => {
                let record = self.trie.lookup(ipv4).unwrap_or(GeoRecord {
                    country_code: "ZZ".to_string(),
                    country_name: "Unknown Network".to_string(),
                    asn: None,
                    as_org: None,
                    is_private: false,
                    is_loopback: false,
                });

                GeoLocationInfo {
                    ip,
                    country_code: record.country_code,
                    country_name: record.country_name,
                    asn: record.asn,
                    as_org: record.as_org,
                    is_private: record.is_private,
                    is_loopback: record.is_loopback,
                }
            }
            IpAddr::V6(ipv6) => {
                let is_loopback = ipv6.is_loopback();
                GeoLocationInfo {
                    ip,
                    country_code: if is_loopback { "LO".to_string() } else { "ZZ".to_string() },
                    country_name: if is_loopback { "Loopback IPv6".to_string() } else { "IPv6 Space".to_string() },
                    asn: None,
                    as_org: None,
                    is_private: is_loopback,
                    is_loopback,
                }
            }
        }
    }
}

pub fn code_to_country_name(code: &str) -> String {
    match code.to_uppercase().as_str() {
        "US" => "United States".to_string(),
        "CA" => "Canada".to_string(),
        "GB" => "United Kingdom".to_string(),
        "DE" => "Germany".to_string(),
        "FR" => "France".to_string(),
        "IN" => "India".to_string(),
        "JP" => "Japan".to_string(),
        "CN" => "China".to_string(),
        "AU" => "Australia".to_string(),
        "NL" => "Netherlands".to_string(),
        "BR" => "Brazil".to_string(),
        "SG" => "Singapore".to_string(),
        "CH" => "Switzerland".to_string(),
        "PR" => "Private Network".to_string(),
        "LO" => "Loopback".to_string(),
        other => format!("Country ({})", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc_classifications() {
        let engine = IpGeoEngine::new();

        let loopback = engine.lookup(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(loopback.is_loopback);
        assert!(loopback.is_private);
        assert_eq!(loopback.country_code, "LO");

        let priv_10 = engine.lookup(IpAddr::V4(Ipv4Addr::new(10, 50, 1, 2)));
        assert!(priv_10.is_private);
        assert!(!priv_10.is_loopback);
        assert_eq!(priv_10.country_code, "PR");

        let priv_192 = engine.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(priv_192.is_private);
        assert_eq!(priv_192.country_code, "PR");

        let public_ip = engine.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!public_ip.is_private);
    }
}

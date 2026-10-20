//! CISA Known Exploited Vulnerabilities (KEV) matching and CVSS scoring.

use std::collections::HashSet;

/// High-priority CISA KEV vulnerability record.
#[derive(Debug, Clone)]
pub struct KevRecord {
    pub cve_id: &'static str,
    pub vendor_project: &'static str,
    pub product: &'static str,
    pub vulnerability_name: &'static str,
    pub date_added: &'static str,
    pub required_action: &'static str,
}

/// Static embedded CISA KEV catalog of critical wild-exploited vulnerabilities.
pub static KNOWN_EXPLOITED_VULNERABILITIES: &[KevRecord] = &[
    KevRecord {
        cve_id: "CVE-2021-44228",
        vendor_project: "Apache",
        product: "Log4j",
        vulnerability_name: "Apache Log4j2 Remote Code Execution (Log4Shell)",
        date_added: "2021-12-10",
        required_action: "Apply vendor updates immediately or disable JNDI lookup.",
    },
    KevRecord {
        cve_id: "CVE-2017-0144",
        vendor_project: "Microsoft",
        product: "Windows SMBv1",
        vulnerability_name: "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
        date_added: "2017-05-12",
        required_action: "Disable SMBv1 across all endpoints and apply MS17-010.",
    },
    KevRecord {
        cve_id: "CVE-2019-0708",
        vendor_project: "Microsoft",
        product: "Remote Desktop Services",
        vulnerability_name: "Remote Desktop Services RCE Vulnerability (BlueKeep)",
        date_added: "2019-05-14",
        required_action: "Apply vendor security update and enforce NLA.",
    },
    KevRecord {
        cve_id: "CVE-2020-1472",
        vendor_project: "Microsoft",
        product: "Netlogon",
        vulnerability_name: "Microsoft Netlogon Elevation of Privilege (Zerologon)",
        date_added: "2020-08-11",
        required_action: "Enforce secure Netlogon channel connections.",
    },
    KevRecord {
        cve_id: "CVE-2021-34527",
        vendor_project: "Microsoft",
        product: "Windows Print Spooler",
        vulnerability_name: "Windows Print Spooler RCE (PrintNightmare)",
        date_added: "2021-07-06",
        required_action: "Disable Print Spooler on domain controllers and servers.",
    },
    KevRecord {
        cve_id: "CVE-2023-38606",
        vendor_project: "Apple",
        product: "iOS and macOS Kernel",
        vulnerability_name: "Apple Kernel Memory Corruption",
        date_added: "2023-07-24",
        required_action: "Apply official Apple OS security updates.",
    },
    KevRecord {
        cve_id: "CVE-2023-34362",
        vendor_project: "Progress",
        product: "MOVEit Transfer",
        vulnerability_name: "MOVEit Transfer SQL Injection Vulnerability",
        date_added: "2023-06-02",
        required_action: "Apply vendor patches and inspect for unauthorized webshells.",
    },
    KevRecord {
        cve_id: "CVE-2024-1709",
        vendor_project: "ConnectWise",
        product: "ScreenConnect",
        vulnerability_name: "ScreenConnect Authentication Bypass Vulnerability",
        date_added: "2024-02-22",
        required_action: "Update ScreenConnect to 23.9.8 or higher.",
    },
];

pub struct KevMatcher {
    kev_set: HashSet<&'static str>,
}

impl Default for KevMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl KevMatcher {
    pub fn new() -> Self {
        let mut set = HashSet::with_capacity(KNOWN_EXPLOITED_VULNERABILITIES.len());
        for k in KNOWN_EXPLOITED_VULNERABILITIES {
            set.insert(k.cve_id);
        }
        Self { kev_set: set }
    }

    /// Check if a CVE ID is listed on CISA's KEV catalog.
    pub fn is_known_exploited(&self, cve_id: &str) -> bool {
        self.kev_set.contains(cve_id)
    }

    /// Get full KEV metadata for a CVE ID.
    pub fn get_kev_details(&self, cve_id: &str) -> Option<&'static KevRecord> {
        KNOWN_EXPLOITED_VULNERABILITIES.iter().find(|k| k.cve_id.eq_ignore_ascii_case(cve_id))
    }
}

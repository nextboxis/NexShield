//! nexshield-cve: High-performance CVE and CISA KEV intelligence search engine.

pub mod index;
pub mod kev;

pub use index::{CveIndex, CveRecord};
pub use kev::{KevMatcher, KevRecord, KNOWN_EXPLOITED_VULNERABILITIES};

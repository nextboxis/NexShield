//! nexshield-scanner: Native high-performance network scanner for NexShield.

pub mod engine;
pub mod prober;
pub mod target;

pub use engine::{scan_target, ScanOptions, ScanOutcome};
pub use prober::{guess_service_by_port, probe_port, ServiceProbeResult};
pub use target::{parse_ports, parse_target, DEFAULT_PORTS, TOP_100_PORTS};

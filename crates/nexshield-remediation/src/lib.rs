//! nexshield-remediation: Automated remediation script and playbook generator for NexShield.

pub mod playbooks;

pub use playbooks::{RemediationBlueprint, RemediationEngine, ScriptFormat, REMEDIATION_CATALOG};

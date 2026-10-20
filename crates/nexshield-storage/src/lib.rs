//! nexshield-storage: In-memory & file-backed document store and authentication system for NexShield.

pub mod crypto;
pub mod store;

pub use crypto::{hash_password, verify_password, Sha256};
pub use store::{ActivityRecord, NexDatabase, ScanJobRecord, UserAccount};

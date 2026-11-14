//! Core Data Structures and Algorithms for NexShield.

pub mod aho_corasick;
pub mod attack_graph;
pub mod bloom;
pub mod ip_trie;
pub mod merkle;
pub mod port_bitmap;
pub mod rate_limiter;
pub mod scheduler;
pub mod top_k;

pub use aho_corasick::{AhoCorasick, AhoCorasickMatch};
pub use attack_graph::AttackGraph;
pub use bloom::ThreatBloomFilter;
pub use ip_trie::IpRadixTrie;
pub use merkle::{MerkleProofStep, MerkleTree};
pub use port_bitmap::PortBitmap;
pub use rate_limiter::TokenBucket;
pub use scheduler::{EventRingBuffer, MinHeapScheduler, ScanScheduleEntry, StreamEvent};
pub use top_k::TopKTracker;

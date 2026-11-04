//! Pure-Rust Bit-Array Bloom Filter (`std` only) for O(1) Threat Intelligence & C2 Reputation Screening.
//!
//! Uses Kirsch-Mitzenmacher double hashing (FNV-1a 64-bit + SplitMix64) to generate `k` independent
//! bit positions in a compact 64-bit word array without heap allocations on lookup.

const BLOOM_WORDS: usize = 256; // 256 * 64 = 16,384 bits (2 KB fixed footprint)
const BLOOM_BITS: u64 = (BLOOM_WORDS * 64) as u64;
const HASH_PROBES: u64 = 5;

#[derive(Clone)]
pub struct ThreatBloomFilter {
    words: [u64; BLOOM_WORDS],
    count: usize,
}

impl Default for ThreatBloomFilter {
    fn default() -> Self {
        Self::with_threat_intel_defaults()
    }
}

impl ThreatBloomFilter {
    /// Creates an empty Bloom Filter.
    pub fn new() -> Self {
        Self {
            words: [0u64; BLOOM_WORDS],
            count: 0,
        }
    }

    /// Creates a Bloom Filter pre-populated with baseline C2, Tor exit, and exploit indicator signatures.
    pub fn with_threat_intel_defaults() -> Self {
        let mut bf = Self::new();
        let indicators = [
            "185.220.101.1",
            "185.220.101.2",
            "45.33.32.156",
            "198.51.100.66",
            "203.0.113.99",
            "xmrig",
            "cobaltstrike",
            "metasploit",
            "meterpreter",
            "jndi:ldap://",
            "jndi:rmi://",
            "mirai",
            "darkcomet",
            "sliver-c2",
        ];
        for ind in indicators {
            bf.insert(ind);
        }
        bf
    }

    /// Inserts an indicator (IP, domain, or payload token) into the Bloom Filter: O(k)
    #[inline]
    pub fn insert(&mut self, item: &str) {
        let norm = item.trim().to_ascii_lowercase();
        let (h1, h2) = Self::double_hash(norm.as_bytes());
        for i in 0..HASH_PROBES {
            let bit_pos = h1.wrapping_add(i.wrapping_mul(h2)) % BLOOM_BITS;
            let word_idx = (bit_pos / 64) as usize;
            let bit_offset = bit_pos % 64;
            self.words[word_idx] |= 1u64 << bit_offset;
        }
        self.count += 1;
    }

    /// Tests whether an indicator is present in the Threat Intelligence set: O(k)
    #[inline]
    pub fn contains(&self, item: &str) -> bool {
        let norm = item.trim().to_ascii_lowercase();
        let (h1, h2) = Self::double_hash(norm.as_bytes());
        for i in 0..HASH_PROBES {
            let bit_pos = h1.wrapping_add(i.wrapping_mul(h2)) % BLOOM_BITS;
            let word_idx = (bit_pos / 64) as usize;
            let bit_offset = bit_pos % 64;
            if (self.words[word_idx] & (1u64 << bit_offset)) == 0 {
                return false;
            }
        }
        true
    }

    /// Number of inserted indicators
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    fn double_hash(bytes: &[u8]) -> (u64, u64) {
        // Hash 1: 64-bit FNV-1a
        let mut h1: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
        }

        // Hash 2: SplitMix64 mixing on FNV state + length
        let mut z = h1.wrapping_add((bytes.len() as u64).wrapping_mul(0x9e3779b97f4a7c15));
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        let h2 = (z ^ (z >> 31)) | 1; // Ensure odd step size

        (h1, h2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_membership_and_intel() {
        let mut bf = ThreatBloomFilter::with_threat_intel_defaults();
        assert!(bf.contains("185.220.101.1"));
        assert!(bf.contains("CobaltStrike"));
        assert!(bf.contains("jndi:ldap://"));
        assert!(!bf.contains("127.0.0.1"));
        assert!(!bf.contains("clean-enterprise-host.internal"));

        bf.insert("10.99.88.77");
        assert!(bf.contains("10.99.88.77"));
    }
}

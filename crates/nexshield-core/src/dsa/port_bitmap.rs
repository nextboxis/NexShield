//! High-performance fixed 65,536-bit port bitmap.
//!
//! Replaces heavy hash sets and Python dicts with a compact 8 KB bit array.
//! Provides O(1) membership testing and hardware-accelerated POPCNT counting.

pub const TOTAL_PORTS: usize = 65536;
const WORDS: usize = TOTAL_PORTS / 64; // 1024 64-bit words = 8192 bytes

#[derive(Clone, PartialEq, Eq)]
pub struct PortBitmap {
    words: [u64; WORDS],
}

impl Default for PortBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl PortBitmap {
    /// Creates an empty PortBitmap (all ports closed)
    pub fn new() -> Self {
        Self { words: [0u64; WORDS] }
    }

    /// Mark a port as open: O(1)
    #[inline]
    pub fn set(&mut self, port: u16) {
        let idx = (port as usize) / 64;
        let bit = (port as usize) % 64;
        self.words[idx] |= 1u64 << bit;
    }

    /// Mark a port as closed: O(1)
    #[inline]
    pub fn unset(&mut self, port: u16) {
        let idx = (port as usize) / 64;
        let bit = (port as usize) % 64;
        self.words[idx] &= !(1u64 << bit);
    }

    /// Test if a port is open: O(1)
    #[inline]
    pub fn contains(&self, port: u16) -> bool {
        let idx = (port as usize) / 64;
        let bit = (port as usize) % 64;
        (self.words[idx] & (1u64 << bit)) != 0
    }

    /// Total count of open ports using CPU hardware POPCNT instructions: O(1024) words
    #[inline]
    pub fn count_open(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Check if no ports are open
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Bitwise intersection (common open ports between two hosts)
    #[inline]
    pub fn intersect(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..WORDS {
            result.words[i] = self.words[i] & other.words[i];
        }
        result
    }

    /// Bitwise union (combined open ports across hosts/scans)
    #[inline]
    pub fn union(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..WORDS {
            result.words[i] = self.words[i] | other.words[i];
        }
        result
    }

    /// Iterate over all open port numbers (1 to 65535)
    pub fn iter_open(&self) -> impl Iterator<Item = u16> + '_ {
        self.words
            .iter()
            .enumerate()
            .filter(|(_, &word)| word != 0)
            .flat_map(|(word_idx, &word)| {
                let mut current_word = word;
                std::iter::from_fn(move || {
                    if current_word == 0 {
                        None
                    } else {
                        let trailing_zeros = current_word.trailing_zeros();
                        let port = (word_idx * 64) + (trailing_zeros as usize);
                        current_word &= current_word - 1; // clear lowest set bit (O(1) assembly BLSR)
                        Some(port as u16)
                    }
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_operations() {
        let mut bm = PortBitmap::new();
        assert!(!bm.contains(80));
        assert!(!bm.contains(443));
        assert_eq!(bm.count_open(), 0);

        bm.set(80);
        bm.set(443);
        bm.set(22);
        bm.set(65535);

        assert!(bm.contains(80));
        assert!(bm.contains(443));
        assert!(bm.contains(22));
        assert!(bm.contains(65535));
        assert!(!bm.contains(8080));
        assert_eq!(bm.count_open(), 4);

        bm.unset(80);
        assert!(!bm.contains(80));
        assert_eq!(bm.count_open(), 3);
    }

    #[test]
    fn test_intersect_and_union() {
        let mut h1 = PortBitmap::new();
        h1.set(80);
        h1.set(443);
        h1.set(22);

        let mut h2 = PortBitmap::new();
        h2.set(80);
        h2.set(3306);
        h2.set(443);

        let common = h1.intersect(&h2);
        assert!(common.contains(80));
        assert!(common.contains(443));
        assert!(!common.contains(22));
        assert!(!common.contains(3306));
        assert_eq!(common.count_open(), 2);

        let union = h1.union(&h2);
        assert_eq!(union.count_open(), 4);
    }

    #[test]
    fn test_iter_open() {
        let mut bm = PortBitmap::new();
        bm.set(22);
        bm.set(80);
        bm.set(443);

        let open_ports: Vec<u16> = bm.iter_open().collect();
        assert_eq!(open_ports, vec![22, 80, 443]);
    }
}

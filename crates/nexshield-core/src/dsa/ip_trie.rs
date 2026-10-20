//! High-performance Binary Radix Trie for IPv4 Longest Prefix Match (LPM).
//!
//! Provides strictly O(1) IP address classification across hundreds of thousands
//! of CIDR blocks, eliminating linear scans and cache misses.

use std::net::Ipv4Addr;

struct TrieNode<T> {
    value: Option<T>,
    children: [Option<Box<TrieNode<T>>>; 2],
}

impl<T> TrieNode<T> {
    fn new() -> Self {
        Self {
            value: None,
            children: [None, None],
        }
    }
}

pub struct IpRadixTrie<T> {
    root: TrieNode<T>,
    len: usize,
}

impl<T: Clone> Default for IpRadixTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> IpRadixTrie<T> {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert a CIDR block prefix: O(prefix_len) <= 32 operations.
    pub fn insert_cidr(&mut self, ip: Ipv4Addr, prefix_len: u8, val: T) {
        let ip_u32 = u32::from(ip);
        let prefix = prefix_len.min(32);
        let mut curr = &mut self.root;

        for i in 0..prefix {
            let bit = ((ip_u32 >> (31 - i)) & 1) as usize;
            if curr.children[bit].is_none() {
                curr.children[bit] = Some(Box::new(TrieNode::new()));
            }
            curr = curr.children[bit].as_mut().unwrap();
        }

        if curr.value.is_none() {
            self.len += 1;
        }
        curr.value = Some(val);
    }

    /// Longest Prefix Match: O(32) <= strictly bounded runtime.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<T> {
        let ip_u32 = u32::from(ip);
        let mut curr = &self.root;
        let mut last_match = curr.value.clone();

        for i in 0..32 {
            let bit = ((ip_u32 >> (31 - i)) & 1) as usize;
            match &curr.children[bit] {
                Some(next) => {
                    curr = next;
                    if curr.value.is_some() {
                        last_match = curr.value.clone();
                    }
                }
                None => break,
            }
        }

        last_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longest_prefix_match() {
        let mut trie = IpRadixTrie::new();

        // 0.0.0.0/0 (Global fallback)
        trie.insert_cidr(Ipv4Addr::new(0, 0, 0, 0), 0, "Global");
        // 192.0.0.0/8 (Broad)
        trie.insert_cidr(Ipv4Addr::new(192, 0, 0, 0), 8, "Broad-192");
        // 192.168.0.0/16 (Private subnet)
        trie.insert_cidr(Ipv4Addr::new(192, 168, 0, 0), 16, "Private-RFC1918");
        // 192.168.1.50/32 (Exact host)
        trie.insert_cidr(Ipv4Addr::new(192, 168, 1, 50), 32, "Specific-Host");

        assert_eq!(trie.lookup(Ipv4Addr::new(8, 8, 8, 8)), Some("Global"));
        assert_eq!(trie.lookup(Ipv4Addr::new(192, 50, 1, 1)), Some("Broad-192"));
        assert_eq!(trie.lookup(Ipv4Addr::new(192, 168, 5, 10)), Some("Private-RFC1918"));
        assert_eq!(trie.lookup(Ipv4Addr::new(192, 168, 1, 50)), Some("Specific-Host"));
    }

    #[test]
    fn test_empty_trie() {
        let trie: IpRadixTrie<&str> = IpRadixTrie::new();
        assert_eq!(trie.lookup(Ipv4Addr::new(10, 0, 0, 1)), None);
    }
}

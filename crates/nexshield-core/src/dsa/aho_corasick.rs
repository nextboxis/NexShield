//! Pure-Rust Aho-Corasick Multi-Pattern Automaton (`std` only).
//!
//! Enables O(N + M) single-pass string matching across hundreds of service banner
//! and vulnerability signatures simultaneously without regex compilation overhead.

use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
struct AcNode {
    transitions: HashMap<u8, usize>,
    fail_link: usize,
    outputs: Vec<usize>,
}

impl AcNode {
    fn new() -> Self {
        Self {
            transitions: HashMap::new(),
            fail_link: 0,
            outputs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AhoCorasickMatch {
    pub pattern_index: usize,
    pub pattern: String,
    pub end_byte: usize,
}

#[derive(Debug, Clone)]
pub struct AhoCorasick {
    nodes: Vec<AcNode>,
    patterns: Vec<String>,
    case_insensitive: bool,
}

impl AhoCorasick {
    /// Builds a compiled Aho-Corasick automaton with failure links constructed via BFS.
    pub fn new(patterns: &[&str], case_insensitive: bool) -> Self {
        let mut nodes = vec![AcNode::new()];
        let mut stored_patterns = Vec::with_capacity(patterns.len());

        // Phase 1: Build Trie
        for (pat_idx, &pat) in patterns.iter().enumerate() {
            let norm = if case_insensitive {
                pat.to_ascii_lowercase()
            } else {
                pat.to_string()
            };
            stored_patterns.push(pat.to_string());

            let mut curr = 0usize;
            for &b in norm.as_bytes() {
                if let Some(&next) = nodes[curr].transitions.get(&b) {
                    curr = next;
                } else {
                    let next = nodes.len();
                    nodes.push(AcNode::new());
                    nodes[curr].transitions.insert(b, next);
                    curr = next;
                }
            }
            nodes[curr].outputs.push(pat_idx);
        }

        // Phase 2: Build Failure Links via Breadth-First Search (BFS)
        let mut queue = VecDeque::new();
        let root_transitions: Vec<(u8, usize)> = nodes[0]
            .transitions
            .iter()
            .map(|(&b, &nxt)| (b, nxt))
            .collect();

        for (_, next_node) in root_transitions {
            nodes[next_node].fail_link = 0;
            queue.push_back(next_node);
        }

        while let Some(curr) = queue.pop_front() {
            let transitions: Vec<(u8, usize)> = nodes[curr]
                .transitions
                .iter()
                .map(|(&b, &nxt)| (b, nxt))
                .collect();

            for (byte, next_node) in transitions {
                queue.push_back(next_node);

                let mut f = nodes[curr].fail_link;
                while f != 0 && !nodes[f].transitions.contains_key(&byte) {
                    f = nodes[f].fail_link;
                }
                let fail_target = nodes[f].transitions.get(&byte).copied().unwrap_or(0);
                nodes[next_node].fail_link = if fail_target == next_node { 0 } else { fail_target };

                // Merge outputs from failure state
                let fail_outputs = nodes[nodes[next_node].fail_link].outputs.clone();
                for out_idx in fail_outputs {
                    if !nodes[next_node].outputs.contains(&out_idx) {
                        nodes[next_node].outputs.push(out_idx);
                    }
                }
            }
        }

        Self {
            nodes,
            patterns: stored_patterns,
            case_insensitive,
        }
    }

    /// Scans `haystack` in a single O(N) pass and returns all matched patterns.
    pub fn find_all(&self, haystack: &str) -> Vec<AhoCorasickMatch> {
        let mut matches = Vec::new();
        let mut state = 0usize;

        for (idx, &raw_byte) in haystack.as_bytes().iter().enumerate() {
            let b = if self.case_insensitive {
                raw_byte.to_ascii_lowercase()
            } else {
                raw_byte
            };

            while state != 0 && !self.nodes[state].transitions.contains_key(&b) {
                state = self.nodes[state].fail_link;
            }
            if let Some(&next) = self.nodes[state].transitions.get(&b) {
                state = next;
            }

            if !self.nodes[state].outputs.is_empty() {
                for &pat_idx in &self.nodes[state].outputs {
                    matches.push(AhoCorasickMatch {
                        pattern_index: pat_idx,
                        pattern: self.patterns[pat_idx].clone(),
                        end_byte: idx + 1,
                    });
                }
            }
        }

        matches
    }

    /// Returns true if any registered pattern appears in `haystack`.
    pub fn is_match(&self, haystack: &str) -> bool {
        let mut state = 0usize;
        for &raw_byte in haystack.as_bytes() {
            let b = if self.case_insensitive {
                raw_byte.to_ascii_lowercase()
            } else {
                raw_byte
            };
            while state != 0 && !self.nodes[state].transitions.contains_key(&b) {
                state = self.nodes[state].fail_link;
            }
            if let Some(&next) = self.nodes[state].transitions.get(&b) {
                state = next;
            }
            if !self.nodes[state].outputs.is_empty() {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aho_corasick_multi_pattern() {
        let signatures = &[
            "openssh_7.",
            "vsftpd 2.3.4",
            "apache/2.4.49",
            "redis_version:",
            "microsoft-iis/7.5",
        ];
        let ac = AhoCorasick::new(signatures, true);

        let banner = "220 (vsFTPd 2.3.4) Ready - Server: Apache/2.4.49 (Unix)";
        let hits = ac.find_all(banner);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].pattern, "vsftpd 2.3.4");
        assert_eq!(hits[1].pattern, "apache/2.4.49");
        assert!(ac.is_match("SSH-2.0-OpenSSH_7.4p1 Debian"));
        assert!(!ac.is_match("SSH-2.0-OpenSSH_9.6p1 Ubuntu"));
    }
}

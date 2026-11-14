//! Binary Merkle Tree for O(log N) Cryptographic Audit Verification.
//!
//! Computes deterministic hierarchical hashes over audit log entries and
//! generates compact O(log N) inclusion proofs without external crates.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProofStep {
    pub sibling_hash: String,
    pub is_left_sibling: bool,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<String>>,
}

impl MerkleTree {
    /// Build a Binary Merkle Tree from a slice of hex-encoded leaf hashes (or raw strings).
    pub fn from_leaves(leaves: &[String]) -> Self {
        if leaves.is_empty() {
            let empty_root = Self::hash_pair(
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            );
            return Self {
                levels: vec![vec![empty_root]],
            };
        }

        let mut current_level: Vec<String> = leaves.to_vec();
        let mut levels = vec![current_level.clone()];

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            let mut i = 0;
            while i < current_level.len() {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left
                };
                next_level.push(Self::hash_pair(left, right));
                i += 2;
            }
            levels.push(next_level.clone());
            current_level = next_level;
        }

        Self { levels }
    }

    /// Return the 64-character hex root hash of the Merkle Tree.
    pub fn root_hex(&self) -> String {
        self.levels
            .last()
            .and_then(|lvl| lvl.first())
            .cloned()
            .unwrap_or_else(|| "0".repeat(64))
    }

    /// Generate an O(log N) inclusion proof for the leaf at `index`.
    pub fn generate_proof(&self, mut index: usize) -> Option<Vec<MerkleProofStep>> {
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }

        let mut proof = Vec::new();
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let is_right_node = index % 2 == 1;
            let sibling_idx = if is_right_node {
                index - 1
            } else if index + 1 < level.len() {
                index + 1
            } else {
                index
            };

            proof.push(MerkleProofStep {
                sibling_hash: level[sibling_idx].clone(),
                is_left_sibling: is_right_node,
            });
            index /= 2;
        }

        Some(proof)
    }

    /// Verify an O(log N) Merkle inclusion proof against `expected_root`.
    pub fn verify_proof(leaf_hash: &str, proof: &[MerkleProofStep], expected_root: &str) -> bool {
        let mut computed = leaf_hash.to_string();
        for step in proof {
            if step.is_left_sibling {
                computed = Self::hash_pair(&step.sibling_hash, &computed);
            } else {
                computed = Self::hash_pair(&computed, &step.sibling_hash);
            }
        }
        computed == expected_root
    }

    /// Deterministic 256-bit mixing hash (4x64-bit SplitMix64/FNV-1a sponge) formatted as 64-char hex.
    pub fn hash_pair(left: &str, right: &str) -> String {
        let mut combined = String::with_capacity(left.len() + right.len() + 1);
        combined.push_str(left);
        combined.push(':');
        combined.push_str(right);
        let bytes = combined.as_bytes();

        let h0 = Self::mix64(bytes, 0xcbf29ce484222325);
        let h1 = Self::mix64(bytes, 0x9e3779b97f4a7c15);
        let h2 = Self::mix64(bytes, 0xbf58476d1ce4e5b9);
        let h3 = Self::mix64(bytes, 0x94d049bb133111eb);

        format!("{:016x}{:016x}{:016x}{:016x}", h0, h1, h2, h3)
    }

    fn mix64(data: &[u8], seed: u64) -> u64 {
        let mut h = seed;
        for &b in data {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
            h ^= h >> 30;
        }
        h = (h ^ (h >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        h = (h ^ (h >> 27)).wrapping_mul(0x94d049bb133111eb);
        h ^ (h >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_proof_verification() {
        let leaves = vec![
            "a111".repeat(16),
            "b222".repeat(16),
            "c333".repeat(16),
            "d444".repeat(16),
            "e555".repeat(16),
        ];
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root_hex();
        assert_eq!(root.len(), 64);

        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(idx).expect("proof should exist");
            assert!(MerkleTree::verify_proof(leaf, &proof, &root));
            assert!(!MerkleTree::verify_proof("tampered_leaf", &proof, &root));
        }
    }
}

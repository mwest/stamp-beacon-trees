//! Stamp/beacon tree construction with per-leaf timing deltas

use sbt_types::{
    messages::{compute_leaf_hash, hash_pair, MerkleNode, MerklePath},
    Digest, Nonce, Timestamp,
};

/// Data for a single leaf in the stamp tree
#[derive(Debug, Clone)]
pub struct LeafData {
    /// The client's digest to be timestamped
    pub digest: Digest,
    /// The unique nonce for this leaf
    pub nonce: Nonce,
    /// The time delta in nanoseconds from the root timestamp
    pub delta_nanos: i64,
}

impl LeafData {
    /// Compute the hash of this leaf
    pub fn compute_hash(&self) -> Digest {
        compute_leaf_hash(&self.digest, &self.nonce)
    }
}

/// A complete stamp/beacon tree
#[derive(Debug)]
pub struct StampTree {
    /// All leaves in the tree (in order)
    leaves: Vec<LeafData>,
    /// The root hash of the tree
    root_hash: Digest,
    /// The root timestamp
    root_timestamp: Timestamp,
    /// Internal nodes organized by level
    /// levels[0] is the leaves, levels[n] is the root
    levels: Vec<Vec<Digest>>,
}

impl StampTree {
    /// Get the root hash
    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    /// Get the root timestamp
    pub fn root_timestamp(&self) -> &Timestamp {
        &self.root_timestamp
    }

    /// Get the number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get a specific leaf
    pub fn get_leaf(&self, index: usize) -> Option<&LeafData> {
        self.leaves.get(index)
    }

    /// Generate a Merkle path for a specific leaf
    pub fn generate_path(&self, leaf_index: usize) -> Option<MerklePath> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut index = leaf_index;

        // Walk up the tree from leaf to root
        for level in 0..self.levels.len() - 1 {
            let level_size = self.levels[level].len();
            let sibling_index = if index % 2 == 0 {
                // We're on the left, sibling is on the right
                index + 1
            } else {
                // We're on the right, sibling is on the left
                index - 1
            };

            // Get the sibling hash (if it exists)
            if sibling_index < level_size {
                let is_left = sibling_index < index;
                siblings.push(MerkleNode {
                    hash: self.levels[level][sibling_index],
                    is_left,
                });
            }

            // Move to parent index
            index /= 2;
        }

        Some(MerklePath {
            leaf_index: leaf_index as u64,
            siblings,
        })
    }
}

/// Builder for constructing stamp/beacon trees
pub struct StampTreeBuilder {
    leaves: Vec<LeafData>,
}

impl StampTreeBuilder {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Add a leaf to the tree
    pub fn add_leaf(&mut self, leaf: LeafData) {
        self.leaves.push(leaf);
    }

    /// Build the tree with a given root timestamp
    pub fn build(self, root_timestamp: Timestamp) -> StampTree {
        let mut levels = Vec::new();

        // Level 0: leaf hashes
        let leaf_hashes: Vec<Digest> = self.leaves.iter().map(|leaf| leaf.compute_hash()).collect();

        if leaf_hashes.is_empty() {
            // Empty tree - use a zero hash
            let zero_hash = Digest::new([0u8; 32]);
            return StampTree {
                leaves: self.leaves,
                root_hash: zero_hash,
                root_timestamp,
                levels: vec![vec![zero_hash]],
            };
        }

        levels.push(leaf_hashes);

        // Build up the tree level by level
        while let Some(prev_level) = levels.last() {
            if prev_level.len() <= 1 {
                break;
            }
            let mut next_level = Vec::new();

            for i in (0..prev_level.len()).step_by(2) {
                let left = &prev_level[i];
                let right = if i + 1 < prev_level.len() {
                    &prev_level[i + 1]
                } else {
                    // Odd number of nodes - duplicate the last one
                    left
                };
                next_level.push(hash_pair(left, right));
            }

            levels.push(next_level);
        }

        // Safe: levels is guaranteed non-empty (we pushed leaf_hashes above)
        let root_hash = levels.last().expect("levels must be non-empty")[0];

        StampTree {
            leaves: self.leaves,
            root_hash,
            root_timestamp,
            levels,
        }
    }
}

impl Default for StampTreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_leaf(digest_byte: u8, nonce_byte: u8, delta: i64) -> LeafData {
        LeafData {
            digest: Digest::new([digest_byte; 32]),
            nonce: Nonce::new([nonce_byte; 32]),
            delta_nanos: delta,
        }
    }

    #[test]
    fn test_single_leaf_tree() {
        let mut builder = StampTreeBuilder::new();
        let leaf = make_test_leaf(1, 2, 0);
        let expected_hash = leaf.compute_hash();
        builder.add_leaf(leaf);

        let tree = builder.build(Timestamp::new(1000, 0).unwrap());

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root_hash(), &expected_hash);
    }

    #[test]
    fn test_two_leaf_tree() {
        let mut builder = StampTreeBuilder::new();
        let leaf0 = make_test_leaf(1, 2, -100);
        let leaf1 = make_test_leaf(3, 4, 100);

        builder.add_leaf(leaf0.clone());
        builder.add_leaf(leaf1.clone());

        let tree = builder.build(Timestamp::new(1000, 0).unwrap());

        assert_eq!(tree.leaf_count(), 2);

        // Verify Merkle paths
        let path0 = tree.generate_path(0).unwrap();
        let path1 = tree.generate_path(1).unwrap();

        assert_eq!(path0.compute_root(&leaf0.compute_hash()), *tree.root_hash());
        assert_eq!(path1.compute_root(&leaf1.compute_hash()), *tree.root_hash());
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let mut builder = StampTreeBuilder::new();
        for i in 0..7 {
            builder.add_leaf(make_test_leaf(i, i + 10, i as i64 * 1000));
        }

        let tree = builder.build(Timestamp::new(1000, 0).unwrap());

        assert_eq!(tree.leaf_count(), 7);

        // Verify all paths
        for i in 0..7 {
            let path = tree.generate_path(i).unwrap();
            let leaf = tree.get_leaf(i).unwrap();
            assert_eq!(
                path.compute_root(&leaf.compute_hash()),
                *tree.root_hash(),
                "Path verification failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_empty_tree() {
        let builder = StampTreeBuilder::new();
        let tree = builder.build(Timestamp::new(1000, 0).unwrap());
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_large_tree() {
        let mut builder = StampTreeBuilder::new();
        for i in 0..100 {
            builder.add_leaf(make_test_leaf(i as u8, (i + 50) as u8, i * 10000));
        }

        let tree = builder.build(Timestamp::new(1000, 0).unwrap());

        // Spot check a few paths
        for i in [0, 42, 99] {
            let path = tree.generate_path(i).unwrap();
            let leaf = tree.get_leaf(i).unwrap();
            assert_eq!(path.compute_root(&leaf.compute_hash()), *tree.root_hash());
        }
    }
}

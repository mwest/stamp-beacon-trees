//! Protocol message definitions for SBT (Stamp/Beacon Tree) protocol

use crate::primitives::{Digest, Nonce, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

/// Request from client to notary for timestamping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampRequest {
    /// Protocol version
    pub version: u32,
    /// Client-submitted digest to be timestamped
    pub digest: Digest,
    /// Client's send timestamp (for clock sync)
    pub client_send_time: Timestamp,
}

/// Response from notary to client with timestamp proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampResponse {
    /// Protocol version
    pub version: u32,
    /// The complete timestamp proof
    pub proof: TimestampProof,
    /// Notary's send timestamp (for clock sync)
    pub notary_send_time: Timestamp,
}

/// A complete timestamp proof that can be independently verified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampProof {
    /// The digest that was timestamped
    pub digest: Digest,
    /// Per-leaf nonce (ensures uniqueness and serves as random beacon)
    pub nonce: Nonce,
    /// Merkle path from leaf to root
    pub merkle_path: MerklePath,
    /// Delta time in nanoseconds from tree root timestamp to this leaf
    /// Negative means this leaf was processed before the root timestamp
    pub delta_nanos: i64,
    /// The tree root timestamp (T)
    pub root_timestamp: Timestamp,
    /// Notary's signature over the tree root
    pub signature: Signature,
    /// Notary's public key for verification
    pub notary_pubkey: PublicKey,
}

impl TimestampProof {
    /// Get the precise timestamp for this leaf
    /// Returns T + delta_nanos
    pub fn leaf_timestamp(&self) -> Timestamp {
        self.root_timestamp.add_nanos(self.delta_nanos)
    }

    /// Compute the leaf hash from digest and nonce
    pub fn compute_leaf_hash(&self) -> Digest {
        compute_leaf_hash(&self.digest, &self.nonce)
    }

    /// Get the timestamp uncertainty (epsilon) in nanoseconds
    /// This is the maximum possible clock uncertainty
    pub fn uncertainty_nanos(&self) -> u64 {
        // TODO: This should be configured based on notary's clock precision
        // For now, using a conservative estimate
        1_000_000 // 1ms
    }
}

/// Merkle path from leaf to root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePath {
    /// The leaf index in the tree
    pub leaf_index: u64,
    /// Sibling hashes needed to compute root
    /// Each entry is (hash, is_left) where is_left indicates if the sibling is on the left
    pub siblings: Vec<MerkleNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: Digest,
    /// True if this sibling is on the left of the path
    pub is_left: bool,
}

impl MerklePath {
    /// Compute the Merkle root from a leaf hash
    pub fn compute_root(&self, leaf_hash: &Digest) -> Digest {
        let mut current = *leaf_hash;

        for sibling in &self.siblings {
            current = if sibling.is_left {
                hash_pair(&sibling.hash, &current)
            } else {
                hash_pair(&current, &sibling.hash)
            };
        }

        current
    }
}

/// Hash a leaf: H(digest || nonce)
pub fn compute_leaf_hash(digest: &Digest, nonce: &Nonce) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(digest.as_bytes());
    hasher.update(nonce.as_bytes());
    let hash = hasher.finalize();
    Digest::new(*hash.as_bytes())
}

/// Hash a pair of nodes: H(left || right)
pub fn hash_pair(left: &Digest, right: &Digest) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let hash = hasher.finalize();
    Digest::new(*hash.as_bytes())
}

/// Domain separation prefix for signature messages.
/// This prevents cross-protocol signature reuse attacks.
pub const SIGN_MESSAGE_PREFIX: &[u8] = b"SBT-v1:";

/// Build a message to be signed by the notary
/// Message format: "SBT-v1:" || root_hash || timestamp_seconds || timestamp_nanos
pub fn build_sign_message(root_hash: &Digest, timestamp: &Timestamp) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGN_MESSAGE_PREFIX.len() + 32 + 8 + 4);
    msg.extend_from_slice(SIGN_MESSAGE_PREFIX);
    msg.extend_from_slice(root_hash.as_bytes());
    msg.extend_from_slice(&timestamp.seconds.to_be_bytes());
    msg.extend_from_slice(&timestamp.nanos.to_be_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_computation() {
        let digest = Digest::new([1u8; 32]);
        let nonce = Nonce::new([2u8; 32]);
        let leaf_hash = compute_leaf_hash(&digest, &nonce);

        // Verify it's deterministic
        let leaf_hash2 = compute_leaf_hash(&digest, &nonce);
        assert_eq!(leaf_hash, leaf_hash2);

        // Different nonce should give different hash
        let nonce2 = Nonce::new([3u8; 32]);
        let leaf_hash3 = compute_leaf_hash(&digest, &nonce2);
        assert_ne!(leaf_hash, leaf_hash3);
    }

    #[test]
    fn test_merkle_path_simple() {
        // Simple 2-leaf tree
        let leaf0 = Digest::new([1u8; 32]);
        let leaf1 = Digest::new([2u8; 32]);

        let root_expected = hash_pair(&leaf0, &leaf1);

        // Path for leaf 0
        let path = MerklePath {
            leaf_index: 0,
            siblings: vec![MerkleNode {
                hash: leaf1,
                is_left: false,
            }],
        };

        let root_computed = path.compute_root(&leaf0);
        assert_eq!(root_expected, root_computed);
    }

    #[test]
    fn test_timestamp_delta() {
        let root_time = Timestamp::new(1000, 0).unwrap();
        let proof = TimestampProof {
            digest: Digest::new([1u8; 32]),
            nonce: Nonce::new([2u8; 32]),
            merkle_path: MerklePath {
                leaf_index: 0,
                siblings: vec![],
            },
            delta_nanos: 500_000_000, // +0.5 seconds
            root_timestamp: root_time,
            signature: Signature::new([0u8; 64]),
            notary_pubkey: PublicKey::new([0u8; 32]),
        };

        let leaf_time = proof.leaf_timestamp();
        assert_eq!(leaf_time.seconds, 1000);
        assert_eq!(leaf_time.nanos, 500_000_000);
    }
}

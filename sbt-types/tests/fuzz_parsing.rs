//! Proptest-based fuzzing for input parsers in sbt-types.
//!
//! These tests exercise deserialization paths with arbitrary/malformed
//! inputs to verify they never panic, only return errors.

use proptest::prelude::*;
use sbt_types::messages::{MerklePath, MerkleNode, TimestampProof};
use sbt_types::{Digest, Nonce, PublicKey, Signature, Timestamp};

proptest! {
    // === JSON deserialization fuzzing (should never panic) ===

    #[test]
    fn fuzz_digest_from_json(s in "\\PC{0,200}") {
        let json = format!("\"{}\"", s);
        let _ = serde_json::from_str::<Digest>(&json);
    }

    #[test]
    fn fuzz_signature_from_json(s in "\\PC{0,200}") {
        let json = format!("\"{}\"", s);
        let _ = serde_json::from_str::<Signature>(&json);
    }

    #[test]
    fn fuzz_public_key_from_json(s in "\\PC{0,200}") {
        let json = format!("\"{}\"", s);
        let _ = serde_json::from_str::<PublicKey>(&json);
    }

    #[test]
    fn fuzz_nonce_from_json(s in "\\PC{0,200}") {
        let json = format!("\"{}\"", s);
        let _ = serde_json::from_str::<Nonce>(&json);
    }

    // === Hex parsing fuzzing ===

    #[test]
    fn fuzz_digest_from_hex(s in "[0-9a-fA-F]{0,200}") {
        let _ = Digest::from_hex(&s);
    }

    #[test]
    fn fuzz_signature_from_hex(s in "[0-9a-fA-F]{0,200}") {
        let _ = Signature::from_hex(&s);
    }

    // === from_slice with arbitrary byte lengths ===

    #[test]
    fn fuzz_digest_from_slice(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Digest::from_slice(&bytes);
    }

    #[test]
    fn fuzz_signature_from_slice(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Signature::from_slice(&bytes);
    }

    #[test]
    fn fuzz_public_key_from_slice(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = PublicKey::from_slice(&bytes);
    }

    #[test]
    fn fuzz_nonce_from_slice(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Nonce::from_slice(&bytes);
    }

    // === Complex type deserialization fuzzing ===

    #[test]
    fn fuzz_timestamp_proof_from_json(json in "\\PC{0,1000}") {
        let _ = serde_json::from_str::<TimestampProof>(&json);
    }

    // === Timestamp construction with boundary values ===

    #[test]
    fn fuzz_timestamp_new(seconds in any::<i64>(), nanos in any::<u32>()) {
        let result = Timestamp::new(seconds, nanos);
        if nanos >= 1_000_000_000 {
            prop_assert!(result.is_err());
        } else {
            prop_assert!(result.is_ok());
        }
    }

    // === MerklePath::compute_root with arbitrary siblings (should never panic) ===

    #[test]
    fn fuzz_merkle_path_compute_root(
        leaf_bytes in prop::array::uniform32(any::<u8>()),
        num_siblings in 0usize..20,
        sibling_data in prop::collection::vec(
            (prop::array::uniform32(any::<u8>()), any::<bool>()),
            0..20
        )
    ) {
        let leaf = Digest::new(leaf_bytes);
        let siblings: Vec<MerkleNode> = sibling_data
            .into_iter()
            .take(num_siblings)
            .map(|(hash_bytes, is_left)| MerkleNode {
                hash: Digest::new(hash_bytes),
                is_left,
            })
            .collect();

        let path = MerklePath {
            leaf_index: 0,
            siblings,
        };

        // Should never panic, regardless of input
        let _root = path.compute_root(&leaf);
    }
}

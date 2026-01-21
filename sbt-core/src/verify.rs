//! Timestamp proof verification

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use thiserror::Error;
use sbt_types::{messages::build_sign_message, TimestampProof};

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Merkle path verification failed")]
    InvalidMerklePath,

    #[error("Signature verification failed")]
    InvalidSignature,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
}

/// Verify a complete timestamp proof
///
/// This performs the following checks:
/// 1. Computes the leaf hash from digest and nonce
/// 2. Verifies the Merkle path leads to the claimed root
/// 3. Verifies the notary's signature on (root_hash || timestamp)
pub fn verify_proof(proof: &TimestampProof) -> Result<(), VerificationError> {
    // Step 1: Compute leaf hash
    let leaf_hash = proof.compute_leaf_hash();

    // Step 2: Compute the Merkle root from the leaf hash and path
    let computed_root = proof.merkle_path.compute_root(&leaf_hash);
    // Note: The Merkle path validity is implicitly verified by the signature check below.
    // If the computed root is wrong, the signature verification will fail.

    // Step 3: Build the message that was signed
    let message = build_sign_message(&computed_root, &proof.root_timestamp);

    // Step 4: Verify signature
    verify_signature(&proof.notary_pubkey, &proof.signature, &message)?;

    Ok(())
}

/// Verify an Ed25519 signature
fn verify_signature(
    public_key: &sbt_types::PublicKey,
    signature: &sbt_types::Signature,
    message: &[u8],
) -> Result<(), VerificationError> {
    // Convert to ed25519-dalek types
    let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|e| VerificationError::InvalidPublicKey(e.to_string()))?;

    let sig = Ed25519Signature::from_bytes(signature.as_bytes());

    verifying_key
        .verify(message, &sig)
        .map_err(|e| VerificationError::InvalidSignature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use sbt_types::{
        messages::{MerkleNode, MerklePath},
        Digest, Nonce, PublicKey, Signature, Timestamp,
    };

    #[test]
    fn test_signature_verification() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message);

        let pubkey = PublicKey::new(*verifying_key.as_bytes());
        let sig = Signature::new(*signature.to_bytes());

        assert!(verify_signature(&pubkey, &sig, message).is_ok());

        // Wrong message should fail
        assert!(verify_signature(&pubkey, &sig, b"wrong message").is_err());
    }

    #[test]
    fn test_full_proof_verification() {
        // Create a simple proof with valid signature
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let digest = Digest::new([1u8; 32]);
        let nonce = Nonce::new([2u8; 32]);
        let timestamp = Timestamp::new(1000, 0).unwrap();

        // Build a simple single-leaf tree
        let leaf_hash = sbt_types::messages::compute_leaf_hash(&digest, &nonce);

        // Sign the root
        let message = build_sign_message(&leaf_hash, &timestamp);
        let signature = signing_key.sign(&message);

        let proof = TimestampProof {
            digest,
            nonce,
            merkle_path: MerklePath {
                leaf_index: 0,
                siblings: vec![],
            },
            delta_nanos: 0,
            root_timestamp: timestamp,
            signature: Signature::new(*signature.to_bytes()),
            notary_pubkey: PublicKey::new(*verifying_key.as_bytes()),
        };

        assert!(verify_proof(&proof).is_ok());
    }

    #[test]
    fn test_invalid_merkle_path_fails() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let digest = Digest::new([1u8; 32]);
        let nonce = Nonce::new([2u8; 32]);
        let timestamp = Timestamp::new(1000, 0).unwrap();

        let leaf_hash = sbt_types::messages::compute_leaf_hash(&digest, &nonce);

        // Sign the correct root
        let message = build_sign_message(&leaf_hash, &timestamp);
        let signature = signing_key.sign(&message);

        // But provide a wrong Merkle path
        let wrong_sibling = Digest::new([99u8; 32]);
        let proof = TimestampProof {
            digest,
            nonce,
            merkle_path: MerklePath {
                leaf_index: 0,
                siblings: vec![MerkleNode {
                    hash: wrong_sibling,
                    is_left: false,
                }],
            },
            delta_nanos: 0,
            root_timestamp: timestamp,
            signature: Signature::new(*signature.to_bytes()),
            notary_pubkey: PublicKey::new(*verifying_key.as_bytes()),
        };

        // This should fail because the Merkle path doesn't match the signature
        assert!(verify_proof(&proof).is_err());
    }
}

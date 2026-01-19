//! Storage for timestamp proofs

use sled::Db;
use sbt_types::{Digest, TimestampProof};

use crate::{ClientError, Result};

/// Storage for timestamp proofs
pub struct ProofStorage {
    db: Db,
}

impl ProofStorage {
    /// Open or create a proof storage at the given path
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let db = sled::open(path)
            .map_err(|e| ClientError::Storage(format!("Failed to open database: {}", e)))?;

        Ok(Self { db })
    }

    /// Store a timestamp proof
    pub fn store(&self, digest: &Digest, proof: &TimestampProof) -> Result<()> {
        let key = digest.as_bytes();
        let value = serde_json::to_vec(proof)
            .map_err(|e| ClientError::Storage(format!("Failed to serialize proof: {}", e)))?;

        self.db
            .insert(key, value)
            .map_err(|e| ClientError::Storage(format!("Failed to store proof: {}", e)))?;

        self.db
            .flush()
            .map_err(|e| ClientError::Storage(format!("Failed to flush database: {}", e)))?;

        Ok(())
    }

    /// Retrieve a timestamp proof
    pub fn get(&self, digest: &Digest) -> Result<Option<TimestampProof>> {
        let key = digest.as_bytes();

        let value = self
            .db
            .get(key)
            .map_err(|e| ClientError::Storage(format!("Failed to retrieve proof: {}", e)))?;

        match value {
            Some(bytes) => {
                let proof = serde_json::from_slice(&bytes)
                    .map_err(|e| ClientError::Storage(format!("Failed to deserialize proof: {}", e)))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// List all stored proofs
    pub fn list(&self) -> Result<Vec<(Digest, TimestampProof)>> {
        let mut proofs = Vec::new();

        for item in self.db.iter() {
            let (key, value) = item
                .map_err(|e| ClientError::Storage(format!("Failed to iterate database: {}", e)))?;

            let digest = Digest::from_slice(&key)
                .map_err(|e| ClientError::Storage(format!("Invalid digest in database: {}", e)))?;

            let proof = serde_json::from_slice(&value)
                .map_err(|e| ClientError::Storage(format!("Failed to deserialize proof: {}", e)))?;

            proofs.push((digest, proof));
        }

        Ok(proofs)
    }

    /// Export a proof as JSON
    pub fn export_json(&self, digest: &Digest) -> Result<String> {
        let proof = self
            .get(digest)?
            .ok_or(ClientError::Storage("Proof not found".to_string()))?;

        serde_json::to_string_pretty(&proof)
            .map_err(|e| ClientError::Storage(format!("Failed to serialize proof: {}", e)))
    }

    /// Import a proof from JSON
    pub fn import_json(&self, json: &str) -> Result<Digest> {
        let proof: TimestampProof = serde_json::from_str(json)
            .map_err(|e| ClientError::Storage(format!("Failed to parse JSON: {}", e)))?;

        let digest = proof.digest.clone();
        self.store(&digest, &proof)?;

        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbt_types::{Nonce, PublicKey, Signature, Timestamp};

    #[test]
    fn test_storage_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = ProofStorage::open(temp_dir.path()).unwrap();

        let digest = Digest::new([1u8; 32]);
        let proof = TimestampProof {
            digest: digest.clone(),
            nonce: Nonce::new([2u8; 32]),
            merkle_path: sbt_types::messages::MerklePath {
                leaf_index: 0,
                siblings: vec![],
            },
            delta_nanos: 0,
            root_timestamp: Timestamp::new(1000, 0).unwrap(),
            signature: Signature::new([0u8; 64]),
            notary_pubkey: PublicKey::new([0u8; 32]),
        };

        storage.store(&digest, &proof).unwrap();

        let retrieved = storage.get(&digest).unwrap();
        assert!(retrieved.is_some());

        let retrieved_proof = retrieved.unwrap();
        assert_eq!(retrieved_proof.digest, proof.digest);
    }
}

//! Client implementation for communicating with notary servers

use std::time::Duration;
use sbt_core::verify_proof;
use sbt_types::{Digest, PublicKey, TimestampProof};

use crate::grpc::{GrpcClient, HealthStatus};
use crate::{ClientError, Result};

/// Client for interacting with an SBT notary server
pub struct SbtClient {
    /// The server URL (for display purposes)
    pub server_url: String,
    /// The connected gRPC client (lazily initialized)
    grpc_client: Option<GrpcClient>,
    timeout: Duration,
}

impl SbtClient {
    /// Create a new client
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            grpc_client: None,
            timeout: Duration::from_secs(10),
        }
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Ensure the gRPC client is connected
    async fn ensure_connected(&mut self) -> Result<&mut GrpcClient> {
        if self.grpc_client.is_none() {
            let client = GrpcClient::connect(&self.server_url).await?;
            self.grpc_client = Some(client);
        }
        Ok(self.grpc_client.as_mut().unwrap())
    }

    /// Submit a digest for timestamping
    pub async fn timestamp(&mut self, digest: Digest) -> Result<TimestampProof> {
        let client = self.ensure_connected().await?;
        let response = client.timestamp(&digest).await?;

        // Verify the proof
        verify_proof(&response.proof)
            .map_err(|e| ClientError::VerificationFailed(e.to_string()))?;

        Ok(response.proof)
    }

    /// Submit a file's hash for timestamping
    pub async fn timestamp_file(&mut self, path: &std::path::Path) -> Result<TimestampProof> {
        let data = std::fs::read(path)
            .map_err(|e| ClientError::Storage(format!("Failed to read file: {}", e)))?;

        let digest = self.hash_data(&data);
        self.timestamp(digest).await
    }

    /// Submit arbitrary data for timestamping
    pub async fn timestamp_data(&mut self, data: &[u8]) -> Result<TimestampProof> {
        let digest = self.hash_data(data);
        self.timestamp(digest).await
    }

    /// Hash data using BLAKE3
    pub fn hash_data(&self, data: &[u8]) -> Digest {
        let hash = blake3::hash(data);
        Digest::new(*hash.as_bytes())
    }

    /// Verify a timestamp proof
    pub fn verify(&self, proof: &TimestampProof) -> Result<()> {
        verify_proof(proof)
            .map_err(|e| ClientError::VerificationFailed(e.to_string()))?;
        Ok(())
    }

    /// Get the notary's public key
    pub async fn get_public_key(&mut self) -> Result<PublicKey> {
        let client = self.ensure_connected().await?;
        client.get_public_key().await
    }

    /// Check server health
    pub async fn health(&mut self) -> Result<HealthStatus> {
        let client = self.ensure_connected().await?;
        client.health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_data() {
        let client = SbtClient::new("http://localhost:8080".to_string());
        let data = b"test data";
        let digest1 = client.hash_data(data);
        let digest2 = client.hash_data(data);
        assert_eq!(digest1, digest2);

        let different_data = b"different data";
        let digest3 = client.hash_data(different_data);
        assert_ne!(digest1, digest3);
    }
}

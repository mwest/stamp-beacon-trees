//! Client implementation for communicating with notary servers

use std::time::Duration;
use sbt_core::verify_proof;
use sbt_types::{Digest, StampRequest, StampResponse, Timestamp, TimestampProof};

use crate::{ClientError, Result};

/// Client for interacting with an SBT notary server
pub struct SbtClient {
    server_url: String,
    timeout: Duration,
}

impl SbtClient {
    /// Create a new client
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            timeout: Duration::from_secs(10),
        }
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Submit a digest for timestamping
    pub async fn timestamp(&self, digest: Digest) -> Result<TimestampProof> {
        let client_send_time = Timestamp::now();

        let request = StampRequest {
            version: 1,
            digest,
            client_send_time,
        };

        // TODO: Implement actual network communication
        // For now, this is a placeholder that would use gRPC/HTTP
        let response = self.send_request(request).await?;

        // Verify the proof
        verify_proof(&response.proof)
            .map_err(|e| ClientError::VerificationFailed(e.to_string()))?;

        Ok(response.proof)
    }

    /// Submit a file's hash for timestamping
    pub async fn timestamp_file(&self, path: &std::path::Path) -> Result<TimestampProof> {
        let data = std::fs::read(path)
            .map_err(|e| ClientError::Storage(format!("Failed to read file: {}", e)))?;

        let digest = self.hash_data(&data);
        self.timestamp(digest).await
    }

    /// Submit arbitrary data for timestamping
    pub async fn timestamp_data(&self, data: &[u8]) -> Result<TimestampProof> {
        let digest = self.hash_data(data);
        self.timestamp(digest).await
    }

    /// Hash data using BLAKE3
    fn hash_data(&self, data: &[u8]) -> Digest {
        let hash = blake3::hash(data);
        Digest::new(*hash.as_bytes())
    }

    /// Verify a timestamp proof
    pub fn verify(&self, proof: &TimestampProof) -> Result<()> {
        verify_proof(proof)
            .map_err(|e| ClientError::VerificationFailed(e.to_string()))?;
        Ok(())
    }

    /// Internal method to send request to server
    async fn send_request(&self, _request: StampRequest) -> Result<StampResponse> {
        // TODO: Implement actual network communication
        // This would use gRPC or HTTP to communicate with the server
        Err(ClientError::Network(
            "Network implementation pending".to_string(),
        ))
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

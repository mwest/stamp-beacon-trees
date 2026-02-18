//! Client implementation for communicating with notary servers

use std::time::Duration;
use sbt_core::verify_proof;
use sbt_types::{Digest, PublicKey, TimestampProof};
use tracing::warn;

use crate::grpc::{GrpcClient, HealthStatus};
use crate::tls::TlsOptions;
use crate::{ClientError, Result};

/// Configuration for retry behavior with exponential backoff
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries)
    pub max_retries: u32,
    /// Initial backoff duration before first retry
    pub initial_backoff: Duration,
    /// Maximum backoff duration (caps exponential growth)
    pub max_backoff: Duration,
    /// Multiplier applied to backoff after each retry
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate the backoff duration for a given attempt (0-indexed)
    fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.initial_backoff.as_secs_f64()
            * self.backoff_multiplier.powi(attempt as i32);
        let capped = base.min(self.max_backoff.as_secs_f64());

        // Add jitter: random value in [0.5 * capped, 1.0 * capped]
        let jitter = 0.5 + rand::random::<f64>() * 0.5;
        Duration::from_secs_f64(capped * jitter)
    }
}

/// Server public key pinning mode
#[derive(Debug, Clone)]
pub enum PinMode {
    /// No pinning — accept any server key
    None,
    /// Trust-On-First-Use: pin the key from the first successful response
    TrustOnFirstUse,
    /// Pre-configured pinned key — reject if server key doesn't match
    Pinned(PublicKey),
}

/// Client for interacting with an SBT notary server
pub struct SbtClient {
    /// The server URL (for display purposes)
    pub server_url: String,
    /// The connected gRPC client (lazily initialized)
    grpc_client: Option<GrpcClient>,
    /// TLS options (None = no TLS)
    tls_options: Option<TlsOptions>,
    /// API key for authentication (optional)
    api_key: Option<String>,
    timeout: Duration,
    /// Retry configuration (None = no retries)
    retry_config: Option<RetryConfig>,
    /// Public key pinning mode
    pin_mode: PinMode,
    /// Stored key for TOFU pinning (set after first successful timestamp)
    pinned_key: Option<PublicKey>,
}

impl SbtClient {
    /// Create a new client (no TLS)
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            grpc_client: None,
            tls_options: None,
            api_key: None,
            timeout: Duration::from_secs(10),
            retry_config: None,
            pin_mode: PinMode::None,
            pinned_key: None,
        }
    }

    /// Create a new client with TLS
    pub fn with_tls(server_url: String, tls_options: TlsOptions) -> Self {
        Self {
            server_url,
            grpc_client: None,
            tls_options: Some(tls_options),
            api_key: None,
            timeout: Duration::from_secs(10),
            retry_config: None,
            pin_mode: PinMode::None,
            pinned_key: None,
        }
    }

    /// Set the API key for authentication
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable retry with the given configuration
    pub fn with_retry(mut self, config: RetryConfig) -> Self {
        self.retry_config = Some(config);
        self
    }

    /// Pin a specific server public key (reject if server key differs)
    pub fn with_pinned_key(mut self, key: PublicKey) -> Self {
        self.pin_mode = PinMode::Pinned(key);
        self
    }

    /// Enable Trust-On-First-Use public key pinning
    pub fn with_tofu(mut self) -> Self {
        self.pin_mode = PinMode::TrustOnFirstUse;
        self
    }

    /// Ensure the gRPC client is connected
    async fn ensure_connected(&mut self) -> Result<&mut GrpcClient> {
        if self.grpc_client.is_none() {
            let mut client = if let Some(tls_options) = &self.tls_options {
                GrpcClient::connect_with_tls(&self.server_url, tls_options).await?
            } else {
                GrpcClient::connect(&self.server_url).await?
            };

            // Set API key if configured
            if let Some(api_key) = &self.api_key {
                client.set_api_key(api_key.clone());
            }

            self.grpc_client = Some(client);
        }
        Ok(self.grpc_client.as_mut().unwrap())
    }

    /// Force reconnection on next call (used after transient errors)
    fn reset_connection(&mut self) {
        self.grpc_client = None;
    }

    /// Check the notary's public key against the pinning policy
    fn check_pinned_key(&mut self, server_key: &PublicKey) -> Result<()> {
        match &self.pin_mode {
            PinMode::None => Ok(()),
            PinMode::Pinned(expected) => {
                if server_key != expected {
                    Err(ClientError::VerificationFailed(
                        "Server public key does not match pinned key".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            PinMode::TrustOnFirstUse => {
                if let Some(pinned) = &self.pinned_key {
                    if server_key != pinned {
                        Err(ClientError::VerificationFailed(
                            "Server public key changed (TOFU violation)".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                } else {
                    // First use — pin this key
                    self.pinned_key = Some(server_key.clone());
                    Ok(())
                }
            }
        }
    }

    /// Submit a digest for timestamping
    pub async fn timestamp(&mut self, digest: Digest) -> Result<TimestampProof> {
        let max_attempts = self.retry_config.as_ref()
            .map(|c| c.max_retries + 1)
            .unwrap_or(1);

        let mut last_err = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let backoff = self.retry_config.as_ref().unwrap()
                    .backoff_for_attempt(attempt - 1);
                warn!(
                    "Retry attempt {}/{} after {:?}",
                    attempt,
                    max_attempts - 1,
                    backoff
                );
                tokio::time::sleep(backoff).await;
                self.reset_connection();
            }

            match self.try_timestamp(&digest).await {
                Ok(proof) => return Ok(proof),
                Err(e) => {
                    if !is_retryable(&e) || attempt + 1 >= max_attempts {
                        return Err(e);
                    }
                    warn!("Retryable error on attempt {}: {}", attempt + 1, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(ClientError::Network("No attempts made".to_string())))
    }

    /// Single attempt at timestamping (no retry)
    async fn try_timestamp(&mut self, digest: &Digest) -> Result<TimestampProof> {
        let client = self.ensure_connected().await?;
        let response = client.timestamp(digest).await?;

        // Verify the proof
        verify_proof(&response.proof)
            .map_err(|e| ClientError::VerificationFailed(e.to_string()))?;

        // Check public key pinning
        self.check_pinned_key(&response.proof.notary_pubkey)?;

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
        let max_attempts = self.retry_config.as_ref()
            .map(|c| c.max_retries + 1)
            .unwrap_or(1);

        let mut last_err = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let backoff = self.retry_config.as_ref().unwrap()
                    .backoff_for_attempt(attempt - 1);
                tokio::time::sleep(backoff).await;
                self.reset_connection();
            }

            let result = async {
                let client = self.ensure_connected().await?;
                client.get_public_key().await
            }.await;

            match result {
                Ok(key) => return Ok(key),
                Err(e) => {
                    if !is_retryable(&e) || attempt + 1 >= max_attempts {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(ClientError::Network("No attempts made".to_string())))
    }

    /// Check server health
    pub async fn health(&mut self) -> Result<HealthStatus> {
        let max_attempts = self.retry_config.as_ref()
            .map(|c| c.max_retries + 1)
            .unwrap_or(1);

        let mut last_err = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let backoff = self.retry_config.as_ref().unwrap()
                    .backoff_for_attempt(attempt - 1);
                tokio::time::sleep(backoff).await;
                self.reset_connection();
            }

            let result = async {
                let client = self.ensure_connected().await?;
                client.health().await
            }.await;

            match result {
                Ok(status) => return Ok(status),
                Err(e) => {
                    if !is_retryable(&e) || attempt + 1 >= max_attempts {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(ClientError::Network("No attempts made".to_string())))
    }
}

/// Determine if an error is retryable (transient network issues)
fn is_retryable(err: &ClientError) -> bool {
    match err {
        ClientError::Network(_) | ClientError::Timeout => true,
        ClientError::VerificationFailed(_)
        | ClientError::InvalidProof
        | ClientError::Storage(_) => false,
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

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
        assert_eq!(config.max_backoff, Duration::from_secs(10));
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_retry_backoff_increases() {
        let config = RetryConfig {
            max_retries: 5,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(60),
            backoff_multiplier: 2.0,
        };

        // Backoff should generally increase (accounting for jitter)
        // attempt 0: base=100ms, attempt 1: base=200ms, attempt 2: base=400ms
        let b0 = config.backoff_for_attempt(0);
        let b2 = config.backoff_for_attempt(2);

        // With jitter [0.5, 1.0], attempt 0 max is 100ms, attempt 2 min is 200ms
        // So b2 should generally be larger, but we check the cap works
        assert!(b0.as_millis() >= 50); // 100ms * 0.5
        assert!(b0.as_millis() <= 100); // 100ms * 1.0
        assert!(b2.as_millis() >= 200); // 400ms * 0.5
        assert!(b2.as_millis() <= 400); // 400ms * 1.0
    }

    #[test]
    fn test_retry_backoff_capped() {
        let config = RetryConfig {
            max_retries: 10,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5),
            backoff_multiplier: 10.0,
        };

        // attempt 5 would be 1s * 10^5 = 100000s, but capped at 5s
        let b = config.backoff_for_attempt(5);
        assert!(b.as_secs_f64() <= 5.0);
    }

    #[test]
    fn test_is_retryable() {
        assert!(is_retryable(&ClientError::Network("connection refused".to_string())));
        assert!(is_retryable(&ClientError::Timeout));
        assert!(!is_retryable(&ClientError::InvalidProof));
        assert!(!is_retryable(&ClientError::VerificationFailed("bad sig".to_string())));
        assert!(!is_retryable(&ClientError::Storage("disk full".to_string())));
    }

    #[test]
    fn test_pin_mode_none() {
        let mut client = SbtClient::new("http://localhost:8080".to_string());
        let key = PublicKey::new([1u8; 32]);
        assert!(client.check_pinned_key(&key).is_ok());
    }

    #[test]
    fn test_pin_mode_pinned_match() {
        let key = PublicKey::new([1u8; 32]);
        let mut client = SbtClient::new("http://localhost:8080".to_string())
            .with_pinned_key(key.clone());
        assert!(client.check_pinned_key(&key).is_ok());
    }

    #[test]
    fn test_pin_mode_pinned_mismatch() {
        let key = PublicKey::new([1u8; 32]);
        let wrong_key = PublicKey::new([2u8; 32]);
        let mut client = SbtClient::new("http://localhost:8080".to_string())
            .with_pinned_key(key);
        assert!(client.check_pinned_key(&wrong_key).is_err());
    }

    #[test]
    fn test_pin_mode_tofu() {
        let mut client = SbtClient::new("http://localhost:8080".to_string())
            .with_tofu();

        let key = PublicKey::new([1u8; 32]);

        // First use: should pin
        assert!(client.check_pinned_key(&key).is_ok());
        assert!(client.pinned_key.is_some());

        // Same key: should succeed
        assert!(client.check_pinned_key(&key).is_ok());

        // Different key: should fail
        let different_key = PublicKey::new([2u8; 32]);
        assert!(client.check_pinned_key(&different_key).is_err());
    }
}

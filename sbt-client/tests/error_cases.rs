//! Error case tests for the SBT client

use std::time::Duration;
use sbt_client::{SbtClient, RetryConfig};

#[tokio::test]
async fn test_connection_refused() {
    // Connect to a port that's not listening
    let mut client = SbtClient::new("http://127.0.0.1:1".to_string());

    let digest = sbt_types::Digest::new([1u8; 32]);
    let result = client.timestamp(digest).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, sbt_client::ClientError::Network(_)),
        "Expected Network error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_retry_exhaustion() {
    // Connect to a port that's not listening, with retries
    let mut client = SbtClient::new("http://127.0.0.1:1".to_string())
        .with_retry(RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            backoff_multiplier: 2.0,
        });

    let digest = sbt_types::Digest::new([1u8; 32]);
    let start = std::time::Instant::now();
    let result = client.timestamp(digest).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Should fail after exhausting retries");

    // Should have waited for at least some backoff time
    // 2 retries with 10ms initial = at least ~10ms + ~20ms = ~30ms minimum
    // (with jitter reducing by half, so at least ~15ms)
    assert!(
        elapsed.as_millis() >= 10,
        "Should have waited for backoff, but only took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_invalid_server_url() {
    let mut client = SbtClient::new("http://not-a-valid-host-xxx:9999".to_string());

    let digest = sbt_types::Digest::new([1u8; 32]);
    let result = client.timestamp(digest).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_health_connection_refused() {
    let mut client = SbtClient::new("http://127.0.0.1:1".to_string());

    let result = client.health().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_public_key_connection_refused() {
    let mut client = SbtClient::new("http://127.0.0.1:1".to_string());

    let result = client.get_public_key().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_retry_on_unavailable() {
    use sbt_notary::testutil::TestServer;

    // Start the server, make a request, verify retries work when server is up
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url())
        .with_retry(RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
        });

    // Should succeed on first attempt since server is up
    let digest = sbt_types::Digest::new([1u8; 32]);
    let result = client.timestamp(digest).await;
    assert!(result.is_ok(), "Should succeed with retry config when server is up");
}

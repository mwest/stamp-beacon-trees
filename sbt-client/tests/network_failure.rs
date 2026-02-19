//! Network failure simulation tests
//!
//! Tests that the client handles server unavailability gracefully
//! with proper error types and retry behavior.

use std::time::Duration;
use sbt_client::{SbtClient, RetryConfig};
use sbt_notary::testutil::TestServer;
use sbt_types::Digest;

/// Test that shutting down the server causes subsequent requests to fail.
#[tokio::test]
async fn test_server_shutdown_causes_failure() {
    let mut server = TestServer::start().await;
    let url = server.url();
    let mut client = SbtClient::new(url.clone());

    // First request should succeed
    let digest = Digest::new([1u8; 32]);
    let proof = client.timestamp(digest).await.expect("first timestamp failed");
    client.verify(&proof).expect("first verification failed");

    // Shut down the server
    server.shutdown();

    // Give OS time to close the socket
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Next request with a fresh client should fail
    let mut new_client = SbtClient::new(url);
    let result = new_client.timestamp(Digest::new([2u8; 32])).await;
    assert!(result.is_err(), "Should fail after server shutdown");
}

/// Test that a client with retries properly fails against a dead server,
/// then succeeds when pointed at a live server.
#[tokio::test]
async fn test_retry_then_new_server() {
    // Try against a port that refuses connections
    let mut client = SbtClient::new("http://127.0.0.1:1".to_string())
        .with_retry(RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
            backoff_multiplier: 2.0,
        });

    let digest = Digest::new([1u8; 32]);
    let result = client.timestamp(digest).await;
    assert!(result.is_err(), "Should fail with server down");

    // Now start a real server and verify a new client works
    let server = TestServer::start().await;
    let mut client2 = SbtClient::new(server.url());

    let proof = client2
        .timestamp(digest)
        .await
        .expect("should succeed with server up");
    client2.verify(&proof).expect("verification failed");
}

/// Test that many rapid connection attempts to a dead server all complete
/// within a reasonable timeout (no resource leaks or hangs).
#[tokio::test]
async fn test_rapid_connection_attempts_no_leak() {
    let mut handles = Vec::new();
    for i in 0u8..20 {
        handles.push(tokio::spawn(async move {
            let mut client = SbtClient::new("http://127.0.0.1:1".to_string());
            let digest = Digest::new([i; 32]);
            let _ = client.timestamp(digest).await;
            // All should fail, but shouldn't panic or hang
        }));
    }

    let timeout = tokio::time::timeout(Duration::from_secs(30), async {
        for handle in handles {
            handle.await.expect("task panicked");
        }
    });

    timeout
        .await
        .expect("Rapid connection test timed out - possible resource leak");
}

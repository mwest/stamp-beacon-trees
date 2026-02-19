//! Large batch integration tests (10k+ requests)
//!
//! These tests verify the system handles realistic load without
//! memory issues, nonce collisions, or proof verification failures.

use std::collections::HashSet;
use sbt_client::SbtClient;
use sbt_notary::testutil::TestServer;
use sbt_notary::config::BatchConfig;
use sbt_types::Digest;

/// Test 10,000 concurrent timestamp requests.
///
/// Validates:
/// - All requests succeed
/// - All nonces are unique
/// - All proofs verify correctly
#[tokio::test]
async fn test_large_batch_10k_concurrent() {
    let server = TestServer::start_with_batch_config(BatchConfig {
        max_batch_size: 500,
        max_wait_ms: 100,
        batch_interval_ms: 100,
    })
    .await;
    let url = server.url();

    let total = 10_000usize;
    let concurrency = 100;
    let per_task = total / concurrency;

    let mut handles = Vec::new();
    for batch_id in 0..concurrency {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let mut client = SbtClient::new(url);
            let mut nonces = Vec::new();

            for i in 0..per_task {
                let global_id = batch_id * per_task + i;
                let mut digest_bytes = [0u8; 32];
                digest_bytes[0..8].copy_from_slice(&(global_id as u64).to_le_bytes());
                let digest = Digest::new(digest_bytes);

                let proof = client
                    .timestamp(digest)
                    .await
                    .unwrap_or_else(|e| panic!("request {} failed: {}", global_id, e));
                client.verify(&proof).expect("verification failed");
                nonces.push(proof.nonce);
            }

            nonces
        }));
    }

    let mut all_nonces = HashSet::new();
    for handle in handles {
        let nonces = handle.await.expect("task panicked");
        for nonce in nonces {
            assert!(all_nonces.insert(nonce), "duplicate nonce detected");
        }
    }

    assert_eq!(all_nonces.len(), total, "Expected {} unique nonces", total);
}

/// Test 1,000 sequential requests to verify no accumulated state issues.
#[tokio::test]
async fn test_large_batch_1k_sequential() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url());

    let mut nonces = HashSet::new();

    for i in 0..1_000usize {
        let mut digest_bytes = [0u8; 32];
        digest_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let digest = Digest::new(digest_bytes);

        let proof = client
            .timestamp(digest)
            .await
            .unwrap_or_else(|e| panic!("sequential request {} failed: {}", i, e));
        client.verify(&proof).expect("verification failed");
        assert!(nonces.insert(proof.nonce), "duplicate nonce at iteration {}", i);
    }

    assert_eq!(nonces.len(), 1_000);
}

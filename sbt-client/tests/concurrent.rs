//! Concurrent request tests for the SBT client

use std::collections::HashSet;
use sbt_client::SbtClient;
use sbt_notary::testutil::TestServer;
use sbt_types::Digest;

#[tokio::test]
async fn test_concurrent_timestamps() {
    let server = TestServer::start().await;
    let url = server.url();

    // Spawn 10 tasks, each timestamping a unique digest
    let mut handles = Vec::new();
    for i in 0u8..10 {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let mut client = SbtClient::new(url);
            let digest = Digest::new([i; 32]);
            let proof = client.timestamp(digest).await
                .unwrap_or_else(|e| panic!("timestamp {} failed: {}", i, e));
            client.verify(&proof).expect("verification failed");
            assert_eq!(proof.digest, digest);
            proof
        }));
    }

    let mut nonces = HashSet::new();
    for handle in handles {
        let proof = handle.await.expect("task panicked");
        // Each proof should have a unique nonce
        assert!(
            nonces.insert(proof.nonce.clone()),
            "Duplicate nonce detected"
        );
    }

    assert_eq!(nonces.len(), 10);
}

#[tokio::test]
async fn test_concurrent_clients() {
    let server = TestServer::start().await;
    let url = server.url();

    // Create 5 separate clients, each making requests concurrently
    let mut handles = Vec::new();
    for client_id in 0u8..5 {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let mut client = SbtClient::new(url);
            let mut proofs = Vec::new();

            for i in 0u8..3 {
                let digest = Digest::new([client_id * 10 + i; 32]);
                let proof = client.timestamp(digest).await
                    .unwrap_or_else(|e| panic!("client {} request {} failed: {}", client_id, i, e));
                client.verify(&proof).expect("verification failed");
                proofs.push(proof);
            }

            proofs
        }));
    }

    let mut all_nonces = HashSet::new();
    let mut total_proofs = 0;

    for handle in handles {
        let proofs = handle.await.expect("task panicked");
        for proof in proofs {
            all_nonces.insert(proof.nonce.clone());
            total_proofs += 1;
        }
    }

    assert_eq!(total_proofs, 15); // 5 clients * 3 requests
    assert_eq!(all_nonces.len(), 15, "All nonces should be unique");
}

#[tokio::test]
async fn test_batch_processing() {
    let server = TestServer::start().await;
    let url = server.url();

    // Send 50 requests rapidly to test batch processing
    let mut handles = Vec::new();
    for i in 0u8..50 {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let mut client = SbtClient::new(url);
            let mut digest_bytes = [0u8; 32];
            digest_bytes[0] = i;
            digest_bytes[1] = i.wrapping_mul(7);
            let digest = Digest::new(digest_bytes);
            let proof = client.timestamp(digest).await
                .unwrap_or_else(|e| panic!("batch request {} failed: {}", i, e));
            client.verify(&proof).expect("verification failed");
            proof
        }));
    }

    let mut nonces = HashSet::new();
    for handle in handles {
        let proof = handle.await.expect("task panicked");
        nonces.insert(proof.nonce.clone());
    }

    assert_eq!(nonces.len(), 50, "All 50 nonces should be unique");
}

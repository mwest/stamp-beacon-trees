//! End-to-end integration tests for the SBT client

use sbt_client::SbtClient;
use sbt_notary::testutil::TestServer;
use sbt_types::{Digest, PublicKey};

#[tokio::test]
async fn test_timestamp_and_verify() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url());

    let digest = Digest::new([42u8; 32]);
    let proof = client.timestamp(digest).await.expect("timestamp failed");

    // Verify the proof
    client.verify(&proof).expect("verification failed");

    // Check the proof contains our digest
    assert_eq!(proof.digest, digest);
}

#[tokio::test]
async fn test_timestamp_data() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url());

    let data = b"Hello, SBT!";
    let proof = client.timestamp_data(data).await.expect("timestamp_data failed");

    client.verify(&proof).expect("verification failed");

    // The digest should match BLAKE3 hash of the data
    let expected_digest = client.hash_data(data);
    assert_eq!(proof.digest, expected_digest);
}

#[tokio::test]
async fn test_timestamp_file() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url());

    // Create a temp file
    let dir = tempfile::tempdir().expect("tempdir failed");
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, b"file content for timestamping").expect("write failed");

    let proof = client.timestamp_file(&file_path).await.expect("timestamp_file failed");

    client.verify(&proof).expect("verification failed");

    // Digest should match the file's BLAKE3 hash
    let data = std::fs::read(&file_path).unwrap();
    let expected_digest = client.hash_data(&data);
    assert_eq!(proof.digest, expected_digest);
}

#[tokio::test]
async fn test_health_check() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url());

    let status = client.health().await.expect("health check failed");

    assert!(status.healthy);
}

#[tokio::test]
async fn test_get_public_key() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url());

    let pubkey = client.get_public_key().await.expect("get_public_key failed");

    // Should match the test server's public key
    assert_eq!(&pubkey, server.public_key());
}

#[tokio::test]
async fn test_multiple_timestamps() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url());

    let mut proofs = Vec::new();

    for i in 0u8..10 {
        let digest = Digest::new([i; 32]);
        let proof = client.timestamp(digest).await
            .unwrap_or_else(|e| panic!("timestamp {} failed: {}", i, e));

        client.verify(&proof).expect("verification failed");
        assert_eq!(proof.digest, digest);

        proofs.push(proof);
    }

    // All proofs should have the same notary public key
    let first_key = &proofs[0].notary_pubkey;
    for proof in &proofs {
        assert_eq!(&proof.notary_pubkey, first_key);
    }
}

#[tokio::test]
async fn test_public_key_pinning_tofu() {
    let server = TestServer::start().await;
    let mut client = SbtClient::new(server.url()).with_tofu();

    // First timestamp: should pin the key
    let digest1 = Digest::new([1u8; 32]);
    let proof1 = client.timestamp(digest1).await.expect("first timestamp failed");
    client.verify(&proof1).expect("verification failed");

    // Second timestamp: should succeed with same key
    let digest2 = Digest::new([2u8; 32]);
    let proof2 = client.timestamp(digest2).await.expect("second timestamp failed");
    client.verify(&proof2).expect("verification failed");

    // Both should have same public key
    assert_eq!(proof1.notary_pubkey, proof2.notary_pubkey);
}

#[tokio::test]
async fn test_public_key_pinning_correct() {
    let server = TestServer::start().await;
    let pinned_key = server.public_key().clone();
    let mut client = SbtClient::new(server.url()).with_pinned_key(pinned_key);

    let digest = Digest::new([1u8; 32]);
    let proof = client.timestamp(digest).await.expect("timestamp with correct pinned key failed");
    client.verify(&proof).expect("verification failed");
}

#[tokio::test]
async fn test_public_key_pinning_mismatch() {
    let server = TestServer::start().await;
    let wrong_key = PublicKey::new([99u8; 32]);
    let mut client = SbtClient::new(server.url()).with_pinned_key(wrong_key);

    let digest = Digest::new([1u8; 32]);
    let result = client.timestamp(digest).await;

    assert!(result.is_err(), "Should fail with pinned key mismatch");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("pinned key"),
        "Error should mention pinned key: {}",
        err
    );
}

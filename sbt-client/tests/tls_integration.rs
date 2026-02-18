//! TLS integration tests for the SBT client
//!
//! Tests TLS connections, mTLS, certificate pinning, and certificate rotation.

use sbt_client::{SbtClient, TlsOptions};
use sbt_notary::testutil::{TestServer, TestCerts};
use sbt_types::Digest;

/// Install the rustls crypto provider (idempotent, safe to call from multiple tests).
fn install_crypto_provider() {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
}

/// Helper: write test certs to a temp directory and return TLS options with CA cert.
fn tls_options_from_certs(certs: &TestCerts, dir: &std::path::Path) -> TlsOptions {
    let (ca_path, _, _, _, _) = certs.write_to_dir(dir);
    TlsOptions::with_ca_cert(ca_path.to_string_lossy().to_string())
}

#[tokio::test]
async fn test_tls_connection() {
    install_crypto_provider();
    let (server, certs) = TestServer::start_with_tls().await;
    let dir = tempfile::tempdir().expect("tempdir failed");
    let tls_options = tls_options_from_certs(&certs, dir.path());

    let mut client = SbtClient::with_tls(server.tls_url(), tls_options);

    let digest = Digest::new([42u8; 32]);
    let proof = client.timestamp(digest).await.expect("TLS timestamp failed");

    client.verify(&proof).expect("TLS proof verification failed");
    assert_eq!(proof.digest, digest);
}

#[tokio::test]
async fn test_mtls_connection() {
    install_crypto_provider();
    let (server, certs) = TestServer::start_with_mtls().await;
    let dir = tempfile::tempdir().expect("tempdir failed");
    let (ca_path, _, _, client_cert_path, client_key_path) = certs.write_to_dir(dir.path());

    let tls_options = TlsOptions::with_ca_cert(ca_path.to_string_lossy().to_string())
        .with_client_cert(
            client_cert_path.to_string_lossy().to_string(),
            client_key_path.to_string_lossy().to_string(),
        );

    let mut client = SbtClient::with_tls(server.tls_url(), tls_options);

    let digest = Digest::new([42u8; 32]);
    let proof = client.timestamp(digest).await.expect("mTLS timestamp failed");

    client.verify(&proof).expect("mTLS proof verification failed");
    assert_eq!(proof.digest, digest);
}

#[tokio::test]
async fn test_tls_cert_pin_correct() {
    install_crypto_provider();
    let (server, certs) = TestServer::start_with_tls().await;
    let dir = tempfile::tempdir().expect("tempdir failed");
    let (ca_path, _, _, _, _) = certs.write_to_dir(dir.path());

    // Compute the SPKI pin from the server certificate
    let pin = sbt_client::compute_spki_pin_from_pem(certs.server_cert_pem.as_bytes())
        .expect("Failed to compute SPKI pin");

    let tls_options = TlsOptions::with_ca_cert(ca_path.to_string_lossy().to_string())
        .with_tls_cert_pin(&pin);

    let mut client = SbtClient::with_tls(server.tls_url(), tls_options);

    let digest = Digest::new([42u8; 32]);
    let proof = client.timestamp(digest).await.expect("Pinned TLS timestamp failed");

    client.verify(&proof).expect("Pinned TLS proof verification failed");
    assert_eq!(proof.digest, digest);
}

#[tokio::test]
async fn test_tls_cert_pin_mismatch() {
    install_crypto_provider();
    let (server, certs) = TestServer::start_with_tls().await;
    let dir = tempfile::tempdir().expect("tempdir failed");
    let (ca_path, _, _, _, _) = certs.write_to_dir(dir.path());

    // Use a wrong pin (base64-encoded SHA-256 of zeros)
    let wrong_pin = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [0u8; 32],
    );

    let tls_options = TlsOptions::with_ca_cert(ca_path.to_string_lossy().to_string())
        .with_tls_cert_pin(&wrong_pin);

    let mut client = SbtClient::with_tls(server.tls_url(), tls_options);

    let digest = Digest::new([42u8; 32]);
    let result = client.timestamp(digest).await;

    assert!(result.is_err(), "Should fail with wrong SPKI pin");
}

#[tokio::test]
async fn test_tls_no_ca_cert_fails() {
    install_crypto_provider();
    let (server, _certs) = TestServer::start_with_tls().await;

    // Try to connect without providing the CA cert — should fail because the
    // server uses a self-signed CA that isn't in system roots.
    let tls_options = TlsOptions::default();
    let mut client = SbtClient::with_tls(server.tls_url(), tls_options);

    let digest = Digest::new([42u8; 32]);
    let result = client.timestamp(digest).await;

    assert!(result.is_err(), "Should fail without CA cert for self-signed server");
}

#[tokio::test]
async fn test_tls_health_check() {
    install_crypto_provider();
    let (server, certs) = TestServer::start_with_tls().await;
    let dir = tempfile::tempdir().expect("tempdir failed");
    let tls_options = tls_options_from_certs(&certs, dir.path());

    let mut client = SbtClient::with_tls(server.tls_url(), tls_options);

    let status = client.health().await.expect("TLS health check failed");
    assert!(status.healthy);
}

#[tokio::test]
async fn test_tls_get_public_key() {
    install_crypto_provider();
    let (server, certs) = TestServer::start_with_tls().await;
    let dir = tempfile::tempdir().expect("tempdir failed");
    let tls_options = tls_options_from_certs(&certs, dir.path());

    let mut client = SbtClient::with_tls(server.tls_url(), tls_options);

    let pubkey = client.get_public_key().await.expect("TLS get_public_key failed");
    assert_eq!(&pubkey, server.public_key());
}

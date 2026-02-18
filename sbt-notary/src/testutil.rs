//! Test utilities for running an in-process notary server without HSM.
//!
//! Enabled via the `test-util` feature flag.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::transport::{Server, ServerTlsConfig, Certificate, Identity};

use crate::batch::BatchProcessor;
use crate::config::BatchConfig;
use crate::grpc::{SbtNotaryService, proto::sbt_notary_server::SbtNotaryServer};
use crate::hsm::{Signer, SoftwareSigner};
use sbt_types::PublicKey;

/// A test notary server that uses a software signer (no HSM required).
///
/// Binds to a random port on localhost and provides the address for client connections.
pub struct TestServer {
    /// The address the server is listening on
    addr: SocketAddr,
    /// The notary's public key
    public_key: PublicKey,
    /// Shutdown signal sender
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl TestServer {
    /// Start a test server on a random port.
    ///
    /// Returns immediately after the server is ready to accept connections.
    pub async fn start() -> Self {
        Self::start_with_batch_config(BatchConfig {
            max_batch_size: 100,
            max_wait_ms: 50,
            batch_interval_ms: 50,
        })
        .await
    }

    /// Start a test server with custom batch configuration.
    pub async fn start_with_batch_config(batch_config: BatchConfig) -> Self {
        let signer = Arc::new(SoftwareSigner::generate());
        let public_key = signer.public_key().clone();

        // Create batch processor channel
        let (request_tx, request_rx) = mpsc::channel(batch_config.max_batch_size * 2);

        // Spawn batch processor
        let batch_processor = BatchProcessor::new(
            batch_config,
            signer.clone(),
            request_rx,
        );
        tokio::spawn(async move {
            batch_processor.run().await;
        });

        // Create gRPC service (no auth, no rate limiting for tests)
        let service = SbtNotaryService::new(request_tx, signer);
        let sbt_service = SbtNotaryServer::new(service);

        // Bind to a random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().expect("Failed to get local address");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Convert TcpListener to the stream type tonic expects
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        tokio::spawn(async move {
            Server::builder()
                .add_service(sbt_service)
                .serve_with_incoming_shutdown(incoming, async {
                    shutdown_rx.await.ok();
                })
                .await
                .expect("Test server failed");
        });

        // Give the server a moment to start accepting connections
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        Self {
            addr,
            public_key,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Get the server's listening address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get the server URL suitable for client connection (e.g., "http://127.0.0.1:12345")
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Get the notary's public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Shut down the test server
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Test TLS certificates generated at runtime using `rcgen`.
///
/// Contains PEM-encoded certificates and keys for CA, server, and client.
#[derive(Debug, Clone)]
pub struct TestCerts {
    /// CA certificate PEM
    pub ca_cert_pem: String,
    /// CA private key PEM (kept for re-signing new server certs in rotation tests)
    pub ca_key_pem: String,
    /// Server certificate PEM (signed by CA, SANs: localhost, 127.0.0.1)
    pub server_cert_pem: String,
    /// Server private key PEM
    pub server_key_pem: String,
    /// Client certificate PEM (signed by CA, for mTLS)
    pub client_cert_pem: String,
    /// Client private key PEM
    pub client_key_pem: String,
}

impl TestCerts {
    /// Generate a fresh set of test certificates.
    ///
    /// Creates a CA, server cert (SANs: localhost, 127.0.0.1), and client cert.
    pub fn generate() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose, SanType,
        };
        use time::{Duration, OffsetDateTime};

        let day = Duration::new(86400, 0);
        let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
        let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();

        // === CA ===
        let mut ca_params = CertificateParams::new(Vec::new())
            .expect("empty SAN list is valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "SBT Test CA");
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
        ca_params.not_before = yesterday;
        ca_params.not_after = tomorrow;

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // === Server cert ===
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("localhost is a valid SAN");
        server_params.subject_alt_names.push(
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        );
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        server_params.use_authority_key_identifier_extension = true;
        server_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        server_params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        server_params.not_before = yesterday;
        server_params.not_after = tomorrow;

        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        // === Client cert ===
        let mut client_params = CertificateParams::new(Vec::new())
            .expect("empty SAN list is valid");
        client_params.distinguished_name.push(DnType::CommonName, "sbt-test-client");
        client_params.use_authority_key_identifier_extension = true;
        client_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        client_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        client_params.not_before = yesterday;
        client_params.not_after = tomorrow;

        let client_key = KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();

        Self {
            ca_cert_pem: ca_cert.pem(),
            ca_key_pem: ca_key.serialize_pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Generate a new server certificate with a different key, signed by the same CA.
    ///
    /// Useful for testing certificate rotation scenarios where the key changes.
    /// Returns (cert_pem, key_pem).
    pub fn generate_new_server_cert(&self) -> (String, String) {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose, SanType,
        };
        use time::{Duration, OffsetDateTime};

        let day = Duration::new(86400, 0);
        let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
        let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();

        // Re-create the CA from stored PEM
        let ca_key = KeyPair::from_pem(&self.ca_key_pem).unwrap();
        let mut ca_params = CertificateParams::new(Vec::new())
            .expect("empty SAN list is valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "SBT Test CA");
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
        ca_params.not_before = yesterday;
        ca_params.not_after = tomorrow;
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Generate new server cert with a new key
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("localhost is a valid SAN");
        server_params.subject_alt_names.push(
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        );
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        server_params.use_authority_key_identifier_extension = true;
        server_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        server_params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        server_params.not_before = yesterday;
        server_params.not_after = tomorrow;

        let new_server_key = KeyPair::generate().unwrap();
        let new_server_cert = server_params
            .signed_by(&new_server_key, &ca_cert, &ca_key)
            .unwrap();

        (new_server_cert.pem(), new_server_key.serialize_pem())
    }

    /// Write certificates to a temporary directory and return the paths.
    ///
    /// Returns (ca_cert_path, server_cert_path, server_key_path, client_cert_path, client_key_path)
    pub fn write_to_dir(&self, dir: &std::path::Path) -> (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let ca_path = dir.join("ca.crt");
        let server_cert_path = dir.join("server.crt");
        let server_key_path = dir.join("server.key");
        let client_cert_path = dir.join("client.crt");
        let client_key_path = dir.join("client.key");

        std::fs::write(&ca_path, &self.ca_cert_pem).unwrap();
        std::fs::write(&server_cert_path, &self.server_cert_pem).unwrap();
        std::fs::write(&server_key_path, &self.server_key_pem).unwrap();
        std::fs::write(&client_cert_path, &self.client_cert_pem).unwrap();
        std::fs::write(&client_key_path, &self.client_key_pem).unwrap();

        (ca_path, server_cert_path, server_key_path, client_cert_path, client_key_path)
    }
}

impl TestServer {
    /// Start a test server with TLS enabled.
    ///
    /// Returns the server and the test certificates used. The server URL
    /// will use `https://` scheme.
    pub async fn start_with_tls() -> (Self, TestCerts) {
        let certs = TestCerts::generate();

        let signer = Arc::new(SoftwareSigner::generate());
        let public_key = signer.public_key().clone();

        let batch_config = BatchConfig {
            max_batch_size: 100,
            max_wait_ms: 50,
            batch_interval_ms: 50,
        };

        // Create batch processor channel
        let (request_tx, request_rx) = mpsc::channel(batch_config.max_batch_size * 2);

        // Spawn batch processor
        let batch_processor = BatchProcessor::new(
            batch_config,
            signer.clone(),
            request_rx,
        );
        tokio::spawn(async move {
            batch_processor.run().await;
        });

        // Create gRPC service
        let service = SbtNotaryService::new(request_tx, signer);
        let sbt_service = SbtNotaryServer::new(service);

        // Configure server TLS
        let server_identity = Identity::from_pem(
            &certs.server_cert_pem,
            &certs.server_key_pem,
        );
        let tls_config = ServerTlsConfig::new().identity(server_identity);

        // Bind to a random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().expect("Failed to get local address");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        tokio::spawn(async move {
            Server::builder()
                .tls_config(tls_config)
                .expect("Failed to configure TLS")
                .add_service(sbt_service)
                .serve_with_incoming_shutdown(incoming, async {
                    shutdown_rx.await.ok();
                })
                .await
                .expect("Test TLS server failed");
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let server = Self {
            addr,
            public_key,
            shutdown_tx: Some(shutdown_tx),
        };

        (server, certs)
    }

    /// Start a test server with mTLS enabled (requires client certificates).
    ///
    /// Returns the server and the test certificates used.
    pub async fn start_with_mtls() -> (Self, TestCerts) {
        let certs = TestCerts::generate();

        let signer = Arc::new(SoftwareSigner::generate());
        let public_key = signer.public_key().clone();

        let batch_config = BatchConfig {
            max_batch_size: 100,
            max_wait_ms: 50,
            batch_interval_ms: 50,
        };

        let (request_tx, request_rx) = mpsc::channel(batch_config.max_batch_size * 2);

        let batch_processor = BatchProcessor::new(
            batch_config,
            signer.clone(),
            request_rx,
        );
        tokio::spawn(async move {
            batch_processor.run().await;
        });

        let service = SbtNotaryService::new(request_tx, signer);
        let sbt_service = SbtNotaryServer::new(service);

        // Configure server TLS with client CA (enables mTLS)
        let server_identity = Identity::from_pem(
            &certs.server_cert_pem,
            &certs.server_key_pem,
        );
        let ca_cert = Certificate::from_pem(&certs.ca_cert_pem);
        let tls_config = ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(ca_cert);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().expect("Failed to get local address");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        tokio::spawn(async move {
            Server::builder()
                .tls_config(tls_config)
                .expect("Failed to configure mTLS")
                .add_service(sbt_service)
                .serve_with_incoming_shutdown(incoming, async {
                    shutdown_rx.await.ok();
                })
                .await
                .expect("Test mTLS server failed");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let server = Self {
            addr,
            public_key,
            shutdown_tx: Some(shutdown_tx),
        };

        (server, certs)
    }

    /// Get the server URL with https:// scheme (for TLS servers).
    pub fn tls_url(&self) -> String {
        format!("https://{}", self.addr)
    }
}

//! TLS configuration for the SBT client

use std::sync::Arc;
use base64::Engine as _;
use sha2::{Sha256, Digest as Sha256Digest};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use tracing::info;

/// TLS certificate pinning configuration.
///
/// Pins the server's TLS certificate by SHA-256 of its Subject Public Key Info (SPKI),
/// following the approach from RFC 7469 (HTTP Public Key Pinning).
///
/// This is distinct from the application-level `PinMode` which pins the notary's
/// Ed25519 signing key. TLS cert pinning operates at the transport layer before
/// any application data is exchanged.
#[derive(Debug, Clone)]
pub struct TlsCertPin {
    /// SHA-256 hash of the server certificate's SPKI, base64-encoded.
    pub spki_sha256: String,
}

/// TLS configuration options for the client
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// Path to CA certificate file (PEM format) for server verification
    pub ca_cert_path: Option<String>,

    /// Path to client certificate file (PEM format) for mTLS
    pub client_cert_path: Option<String>,

    /// Path to client private key file (PEM format) for mTLS
    pub client_key_path: Option<String>,

    /// Server domain name for TLS verification (defaults to host from URL)
    pub domain_name: Option<String>,

    /// Skip TLS certificate verification (DANGEROUS - for testing only)
    pub insecure_skip_verify: bool,

    /// TLS certificate pin (SHA-256 of server cert's SPKI, base64-encoded).
    /// When set, the client verifies that the server certificate's SPKI hash
    /// matches this pin during the TLS handshake.
    pub tls_cert_pin: Option<TlsCertPin>,
}

impl TlsOptions {
    /// Create new TLS options with CA certificate for server verification
    pub fn with_ca_cert(ca_cert_path: impl Into<String>) -> Self {
        Self {
            ca_cert_path: Some(ca_cert_path.into()),
            ..Default::default()
        }
    }

    /// Add client certificate for mTLS authentication
    pub fn with_client_cert(
        mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        self.client_cert_path = Some(cert_path.into());
        self.client_key_path = Some(key_path.into());
        self
    }

    /// Set the server domain name for TLS verification
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain_name = Some(domain.into());
        self
    }

    /// Skip TLS verification (DANGEROUS - for testing only)
    pub fn insecure(mut self) -> Self {
        self.insecure_skip_verify = true;
        self
    }

    /// Set TLS certificate pin (SHA-256 of server cert's SPKI, base64-encoded).
    /// Use `compute_spki_pin_from_pem()` or `scripts/generate-certs.sh` to obtain the pin.
    pub fn with_tls_cert_pin(mut self, spki_sha256: impl Into<String>) -> Self {
        self.tls_cert_pin = Some(TlsCertPin {
            spki_sha256: spki_sha256.into(),
        });
        self
    }

    /// Check if TLS is configured
    pub fn is_enabled(&self) -> bool {
        self.ca_cert_path.is_some() || self.insecure_skip_verify
    }

    /// Check if TLS cert pinning is configured
    pub fn has_cert_pin(&self) -> bool {
        self.tls_cert_pin.is_some()
    }
}

/// Load TLS configuration for the client (standard tonic path, no cert pinning)
pub fn load_client_tls_config(options: &TlsOptions) -> Result<ClientTlsConfig, Box<dyn std::error::Error>> {
    let mut tls_config = ClientTlsConfig::new();

    // Set domain name if provided
    if let Some(domain) = &options.domain_name {
        tls_config = tls_config.domain_name(domain.clone());
    }

    // Load CA certificate for server verification
    if let Some(ca_cert_path) = &options.ca_cert_path {
        info!("Loading CA certificate from {}", ca_cert_path);
        let ca_cert_pem = std::fs::read(ca_cert_path)
            .map_err(|e| format!("Failed to read CA certificate file {}: {}", ca_cert_path, e))?;
        let ca_cert = Certificate::from_pem(ca_cert_pem);
        tls_config = tls_config.ca_certificate(ca_cert);
    }

    // Load client certificate for mTLS if provided
    if let (Some(cert_path), Some(key_path)) = (&options.client_cert_path, &options.client_key_path) {
        info!("Loading client certificate from {}", cert_path);
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| format!("Failed to read client certificate file {}: {}", cert_path, e))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| format!("Failed to read client key file {}: {}", key_path, e))?;
        let identity = Identity::from_pem(cert_pem, key_pem);
        tls_config = tls_config.identity(identity);
    }

    Ok(tls_config)
}

/// Build a rustls `ClientConfig` with SPKI certificate pinning.
///
/// This creates a custom TLS configuration that verifies the server certificate's
/// SPKI hash matches the expected pin, in addition to standard CA verification.
pub fn build_pinned_rustls_config(
    options: &TlsOptions,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

    // Ensure a crypto provider is installed (idempotent if already set)
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    let pin = options.tls_cert_pin.as_ref()
        .ok_or("TLS cert pin not configured")?;

    let expected_pin = base64::engine::general_purpose::STANDARD
        .decode(&pin.spki_sha256)
        .map_err(|e| format!("Invalid base64 in TLS cert pin: {}", e))?;

    if expected_pin.len() != 32 {
        return Err(format!(
            "TLS cert pin must be 32 bytes (SHA-256), got {} bytes",
            expected_pin.len()
        ).into());
    }

    let mut pin_bytes = [0u8; 32];
    pin_bytes.copy_from_slice(&expected_pin);

    // Build root certificate store
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_cert_path) = &options.ca_cert_path {
        let ca_pem = std::fs::read(ca_cert_path)
            .map_err(|e| format!("Failed to read CA cert: {}", e))?;
        let mut cursor = std::io::Cursor::new(&ca_pem);
        let certs = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse CA cert PEM: {}", e))?;
        for cert in certs {
            root_store.add(cert)?;
        }
    }

    // Create the default verifier
    let default_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| format!("Failed to build default verifier: {}", e))?;

    /// Custom server certificate verifier that adds SPKI pin checking
    /// on top of standard WebPKI verification.
    #[derive(Debug)]
    struct SpkiPinVerifier {
        inner: Arc<dyn ServerCertVerifier>,
        expected_pin: [u8; 32],
    }

    impl ServerCertVerifier for SpkiPinVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            // First, do standard WebPKI verification
            self.inner.verify_server_cert(
                end_entity, intermediates, server_name, ocsp_response, now,
            )?;

            // Then check the SPKI pin
            let actual_pin = compute_spki_pin(end_entity.as_ref())
                .map_err(|e| RustlsError::General(format!("Failed to compute SPKI pin: {}", e)))?;

            if actual_pin != self.expected_pin {
                return Err(RustlsError::General(
                    "TLS certificate SPKI pin mismatch".to_string(),
                ));
            }

            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    let pinning_verifier = SpkiPinVerifier {
        inner: default_verifier,
        expected_pin: pin_bytes,
    };

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinning_verifier))
        .with_no_client_auth();

    // Load client cert for mTLS if configured
    if let (Some(cert_path), Some(key_path)) = (&options.client_cert_path, &options.client_key_path) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| format!("Failed to read client cert: {}", e))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| format!("Failed to read client key: {}", e))?;

        let mut cert_cursor = std::io::Cursor::new(&cert_pem);
        let certs = rustls_pemfile::certs(&mut cert_cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse client cert PEM: {}", e))?;

        let mut key_cursor = std::io::Cursor::new(&key_pem);
        let key = rustls_pemfile::private_key(&mut key_cursor)
            .map_err(|e| format!("Failed to parse client key PEM: {}", e))?
            .ok_or("No private key found in client key file")?;

        config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SpkiPinVerifier {
                inner: {
                    let mut root_store2 = rustls::RootCertStore::empty();
                    if let Some(ca_cert_path) = &options.ca_cert_path {
                        let ca_pem = std::fs::read(ca_cert_path)?;
                        let mut cursor = std::io::Cursor::new(&ca_pem);
                        let certs_list = rustls_pemfile::certs(&mut cursor)
                            .collect::<Result<Vec<_>, _>>()?;
                        for c in certs_list {
                            root_store2.add(c)?;
                        }
                    }
                    rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store2))
                        .build()?
                },
                expected_pin: pin_bytes,
            }))
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("Failed to set client auth cert: {}", e))?;
    }

    // Set ALPN protocols for HTTP/2 (required by tonic/gRPC)
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(config)
}

/// Compute the SHA-256 SPKI pin for a DER-encoded certificate.
/// Returns the raw 32-byte hash.
pub fn compute_spki_pin(cert_der: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {}", e))?;

    let spki_der = cert.public_key().raw;
    let hash = Sha256::digest(spki_der);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    Ok(result)
}

/// Compute the SPKI pin from a PEM-encoded certificate and return it as base64.
pub fn compute_spki_pin_from_pem(cert_pem: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut cursor = std::io::Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse PEM: {}", e))?;

    let cert = certs.first().ok_or("No certificate found in PEM")?;
    let pin = compute_spki_pin(cert.as_ref())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(pin))
}

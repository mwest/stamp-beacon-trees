//! TLS configuration for the SBT client

use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use tracing::info;

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

    /// Check if TLS is configured
    pub fn is_enabled(&self) -> bool {
        self.ca_cert_path.is_some() || self.insecure_skip_verify
    }
}

/// Load TLS configuration for the client
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

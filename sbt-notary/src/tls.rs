//! TLS configuration and utilities for the notary server

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls_pemfile::{certs, private_key};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use tonic::transport::{Identity, ServerTlsConfig, Certificate};
use tracing::info;

use crate::config::TlsConfig;

/// Load TLS configuration for the server
pub fn load_server_tls_config(config: &TlsConfig) -> Result<ServerTlsConfig, Box<dyn std::error::Error>> {
    info!("Loading TLS certificates from {:?}", config.cert_path);

    // Read server certificate
    let cert_pem = std::fs::read(&config.cert_path)
        .map_err(|e| format!("Failed to read certificate file {:?}: {}", config.cert_path, e))?;

    // Read server private key
    let key_pem = std::fs::read(&config.key_path)
        .map_err(|e| format!("Failed to read key file {:?}: {}", config.key_path, e))?;

    let identity = Identity::from_pem(cert_pem, key_pem);

    let mut tls_config = ServerTlsConfig::new().identity(identity);

    // If CA cert is provided, enable client certificate verification (mTLS)
    if let Some(ca_cert_path) = &config.ca_cert_path {
        info!("Enabling mTLS with CA certificate from {:?}", ca_cert_path);

        let ca_cert_pem = std::fs::read(ca_cert_path)
            .map_err(|e| format!("Failed to read CA certificate file {:?}: {}", ca_cert_path, e))?;

        let ca_cert = Certificate::from_pem(ca_cert_pem);
        tls_config = tls_config.client_ca_root(ca_cert);
    }

    Ok(tls_config)
}

/// Load certificates from PEM file
fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse certificates: {}", e))?;
    Ok(certs)
}

/// Load private key from PEM file
fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = private_key(&mut reader)
        .map_err(|e| format!("Failed to parse private key: {}", e))?
        .ok_or("No private key found in file")?;
    Ok(key)
}

//! Notary configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryConfig {
    /// Server configuration
    pub server: ServerConfig,

    /// HSM configuration
    pub hsm: HsmConfig,

    /// Batch processing configuration
    pub batch: BatchConfig,

    /// TLS configuration (optional)
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,

    /// Port to bind to
    pub port: u16,

    /// Maximum concurrent connections
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to server certificate file (PEM format)
    pub cert_path: PathBuf,

    /// Path to server private key file (PEM format)
    pub key_path: PathBuf,

    /// Path to CA certificate for client verification (optional, enables mTLS)
    pub ca_cert_path: Option<PathBuf>,

    /// Require client certificates (mTLS)
    #[serde(default)]
    pub require_client_cert: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// Path to PKCS#11 library
    pub pkcs11_library: PathBuf,

    /// Slot ID for the HSM
    pub slot_id: u64,

    /// PIN for HSM access (should be provided via environment variable)
    #[serde(skip)]
    pub pin: Option<String>,

    /// Key label in the HSM
    pub key_label: String,

    /// Key ID in the HSM (alternative to label)
    pub key_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Maximum batch size (number of requests)
    pub max_batch_size: usize,

    /// Maximum wait time before processing batch (milliseconds)
    pub max_wait_ms: u64,

    /// Target batch interval (milliseconds)
    /// This determines how frequently trees are built
    pub batch_interval_ms: u64,
}

impl Default for NotaryConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                max_connections: 1000,
            },
            hsm: HsmConfig {
                pkcs11_library: PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
                slot_id: 0,
                pin: None,
                key_label: "sbt-notary-key".to_string(),
                key_id: None,
            },
            batch: BatchConfig {
                max_batch_size: 1000,
                max_wait_ms: 100,
                batch_interval_ms: 1000,
            },
            tls: None,
        }
    }
}

impl NotaryConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: NotaryConfig = toml::from_str(&contents)?;

        // Load PIN from environment variable if not set
        if config.hsm.pin.is_none() {
            config.hsm.pin = std::env::var("SBT_HSM_PIN").ok();
        }

        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

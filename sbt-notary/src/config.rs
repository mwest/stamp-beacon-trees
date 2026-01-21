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

    /// Rate limiting configuration (optional)
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum requests per second per client IP
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,

    /// Maximum burst size per client IP (token bucket capacity)
    #[serde(default = "default_per_ip_burst")]
    pub per_ip_burst: u32,

    /// Maximum global requests per second (across all clients)
    #[serde(default = "default_global_rps")]
    pub global_rps: u32,

    /// Maximum global burst size
    #[serde(default = "default_global_burst")]
    pub global_burst: u32,

    /// Maximum request body size in bytes (default: 1KB for a digest)
    #[serde(default = "default_max_request_size")]
    pub max_request_size: usize,

    /// Cleanup interval for expired rate limit entries (seconds)
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,

    /// Time-to-live for client rate limit entries (seconds)
    #[serde(default = "default_entry_ttl")]
    pub entry_ttl_secs: u64,
}

fn default_enabled() -> bool { true }
fn default_per_ip_rps() -> u32 { 100 }
fn default_per_ip_burst() -> u32 { 200 }
fn default_global_rps() -> u32 { 10000 }
fn default_global_burst() -> u32 { 20000 }
fn default_max_request_size() -> usize { 1024 } // 1KB
fn default_cleanup_interval() -> u64 { 60 }
fn default_entry_ttl() -> u64 { 300 }

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            per_ip_rps: default_per_ip_rps(),
            per_ip_burst: default_per_ip_burst(),
            global_rps: default_global_rps(),
            global_burst: default_global_burst(),
            max_request_size: default_max_request_size(),
            cleanup_interval_secs: default_cleanup_interval(),
            entry_ttl_secs: default_entry_ttl(),
        }
    }
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
            rate_limit: None,
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

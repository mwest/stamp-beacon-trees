//! Authentication and authorization module
//!
//! Supports API key authentication and mTLS client certificate verification.

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::{ApiKeyEntry, AuthConfig, AuthMode};

/// Authentication error types
#[derive(Debug, Clone)]
pub enum AuthError {
    /// No credentials provided
    MissingCredentials,
    /// Invalid API key
    InvalidApiKey,
    /// API key is disabled
    KeyDisabled { key_id: String },
    /// mTLS required but no client certificate
    MtlsRequired,
    /// Authentication is required
    AuthenticationRequired,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingCredentials => write!(f, "No authentication credentials provided"),
            AuthError::InvalidApiKey => write!(f, "Invalid API key"),
            AuthError::KeyDisabled { key_id } => write!(f, "API key '{}' is disabled", key_id),
            AuthError::MtlsRequired => write!(f, "Client certificate required"),
            AuthError::AuthenticationRequired => write!(f, "Authentication required"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Result of successful authentication
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// How the client was authenticated
    pub method: AuthMethod,
    /// Client identifier (key_id or certificate subject)
    pub client_id: String,
}

/// Authentication method used
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    /// Authenticated via API key
    ApiKey,
    /// Authenticated via mTLS client certificate
    MtlsCertificate,
    /// Anonymous access (allowed for certain endpoints)
    Anonymous,
}

/// Authenticator that validates API keys and manages authentication state
pub struct Authenticator {
    config: AuthConfig,
    /// API keys indexed by secret for O(1) lookup
    api_keys: Arc<RwLock<HashMap<String, ApiKeyEntry>>>,
}

impl Authenticator {
    /// Create a new authenticator from configuration
    pub fn new(config: AuthConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut keys_map = HashMap::new();

        // Load keys from config
        for entry in &config.api_keys {
            if entry.secret.is_empty() {
                warn!("Skipping API key '{}' with empty secret", entry.key_id);
                continue;
            }
            keys_map.insert(entry.secret.clone(), entry.clone());
        }

        // Load keys from file if specified
        if let Some(keys_file) = &config.api_keys_file {
            let file_keys = Self::load_keys_from_file(keys_file)?;
            for entry in file_keys {
                keys_map.insert(entry.secret.clone(), entry);
            }
        }

        // Load keys from environment variable
        if let Ok(env_keys) = std::env::var("SBT_API_KEYS") {
            let env_entries = Self::parse_keys_string(&env_keys);
            for entry in env_entries {
                keys_map.insert(entry.secret.clone(), entry);
            }
        }

        let key_count = keys_map.len();
        if config.enabled && key_count == 0 && config.mode != AuthMode::MtlsOnly {
            warn!("Authentication enabled but no API keys configured");
        } else if key_count > 0 {
            info!("Loaded {} API key(s)", key_count);
        }

        Ok(Self {
            config,
            api_keys: Arc::new(RwLock::new(keys_map)),
        })
    }

    /// Load API keys from a file
    fn load_keys_from_file(path: &std::path::Path) -> Result<Vec<ApiKeyEntry>, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let mut entries = Vec::new();

        for (line_num, line) in contents.lines().enumerate() {
            let line = line.trim();
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let entry = if let Some((key_id, secret)) = line.split_once(':') {
                ApiKeyEntry {
                    key_id: key_id.trim().to_string(),
                    secret: secret.trim().to_string(),
                    description: None,
                    enabled: true,
                }
            } else {
                // Just a secret, generate key_id
                ApiKeyEntry {
                    key_id: format!("file_key_{}", line_num + 1),
                    secret: line.to_string(),
                    description: Some(format!("Loaded from file line {}", line_num + 1)),
                    enabled: true,
                }
            };

            if entry.secret.is_empty() {
                warn!("Skipping empty key on line {}", line_num + 1);
                continue;
            }

            entries.push(entry);
        }

        info!("Loaded {} API key(s) from file", entries.len());
        Ok(entries)
    }

    /// Parse keys from a string (for environment variable)
    fn parse_keys_string(keys_str: &str) -> Vec<ApiKeyEntry> {
        let mut entries = Vec::new();

        // Format: "key_id1:secret1,key_id2:secret2" or "secret1,secret2"
        for (idx, part) in keys_str.split(',').enumerate() {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let entry = if let Some((key_id, secret)) = part.split_once(':') {
                ApiKeyEntry {
                    key_id: key_id.trim().to_string(),
                    secret: secret.trim().to_string(),
                    description: Some("Loaded from environment".to_string()),
                    enabled: true,
                }
            } else {
                ApiKeyEntry {
                    key_id: format!("env_key_{}", idx + 1),
                    secret: part.to_string(),
                    description: Some("Loaded from environment".to_string()),
                    enabled: true,
                }
            };

            entries.push(entry);
        }

        if !entries.is_empty() {
            info!("Loaded {} API key(s) from environment", entries.len());
        }

        entries
    }

    /// Check if authentication is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if anonymous access is allowed for health/public key endpoints
    pub fn allow_anonymous_health(&self) -> bool {
        !self.config.enabled || self.config.allow_anonymous_health
    }

    /// Check if anonymous access is allowed for timestamp endpoint
    pub fn allow_anonymous_timestamp(&self) -> bool {
        !self.config.enabled || self.config.allow_anonymous_timestamp
    }

    /// Get the authentication mode
    pub fn mode(&self) -> &AuthMode {
        &self.config.mode
    }

    /// Validate an API key
    pub async fn validate_api_key(&self, key: &str) -> Result<AuthContext, AuthError> {
        if key.is_empty() {
            return Err(AuthError::MissingCredentials);
        }

        let keys = self.api_keys.read().await;

        if let Some(entry) = keys.get(key) {
            if !entry.enabled {
                return Err(AuthError::KeyDisabled {
                    key_id: entry.key_id.clone(),
                });
            }

            debug!("API key '{}' authenticated successfully", entry.key_id);

            Ok(AuthContext {
                method: AuthMethod::ApiKey,
                client_id: entry.key_id.clone(),
            })
        } else {
            Err(AuthError::InvalidApiKey)
        }
    }

    /// Authenticate a request
    ///
    /// Arguments:
    /// - `api_key`: Optional API key from header
    /// - `has_client_cert`: Whether the client provided a valid mTLS certificate
    /// - `cert_subject`: Client certificate subject (if mTLS)
    /// - `is_health_endpoint`: Whether this is a health/public key endpoint
    pub async fn authenticate(
        &self,
        api_key: Option<&str>,
        has_client_cert: bool,
        cert_subject: Option<&str>,
        is_health_endpoint: bool,
    ) -> Result<AuthContext, AuthError> {
        // If authentication is disabled, allow anonymous
        if !self.config.enabled {
            return Ok(AuthContext {
                method: AuthMethod::Anonymous,
                client_id: "anonymous".to_string(),
            });
        }

        // Check if anonymous access is allowed for this endpoint type
        if is_health_endpoint && self.config.allow_anonymous_health {
            return Ok(AuthContext {
                method: AuthMethod::Anonymous,
                client_id: "anonymous".to_string(),
            });
        }

        match &self.config.mode {
            AuthMode::ApiKey => {
                // API key is required
                if let Some(key) = api_key {
                    self.validate_api_key(key).await
                } else {
                    Err(AuthError::MissingCredentials)
                }
            }

            AuthMode::MtlsOnly => {
                // mTLS is required
                if has_client_cert {
                    Ok(AuthContext {
                        method: AuthMethod::MtlsCertificate,
                        client_id: cert_subject.unwrap_or("unknown").to_string(),
                    })
                } else {
                    Err(AuthError::MtlsRequired)
                }
            }

            AuthMode::Hybrid => {
                // Either API key or mTLS is sufficient
                if has_client_cert {
                    return Ok(AuthContext {
                        method: AuthMethod::MtlsCertificate,
                        client_id: cert_subject.unwrap_or("unknown").to_string(),
                    });
                }

                if let Some(key) = api_key {
                    return self.validate_api_key(key).await;
                }

                Err(AuthError::MissingCredentials)
            }
        }
    }

    /// Add or update an API key at runtime
    pub async fn add_api_key(&self, entry: ApiKeyEntry) {
        let mut keys = self.api_keys.write().await;
        info!("Adding API key '{}'", entry.key_id);
        keys.insert(entry.secret.clone(), entry);
    }

    /// Remove an API key at runtime
    pub async fn remove_api_key(&self, key_id: &str) -> bool {
        let mut keys = self.api_keys.write().await;
        let initial_len = keys.len();
        keys.retain(|_, entry| entry.key_id != key_id);
        let removed = keys.len() < initial_len;
        if removed {
            info!("Removed API key '{}'", key_id);
        }
        removed
    }

    /// Disable an API key at runtime
    pub async fn disable_api_key(&self, key_id: &str) -> bool {
        let mut keys = self.api_keys.write().await;
        for entry in keys.values_mut() {
            if entry.key_id == key_id {
                entry.enabled = false;
                info!("Disabled API key '{}'", key_id);
                return true;
            }
        }
        false
    }

    /// Get the number of configured API keys
    pub async fn key_count(&self) -> usize {
        self.api_keys.read().await.len()
    }
}

/// Generate a cryptographically secure API key
pub fn generate_api_key() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    // Use URL-safe base64 encoding
    base64_encode_urlsafe(&bytes)
}

/// URL-safe base64 encoding without padding
fn base64_encode_urlsafe(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity((data.len() * 4 + 2) / 3);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AuthConfig {
        AuthConfig {
            enabled: true,
            mode: AuthMode::ApiKey,
            api_keys: vec![
                ApiKeyEntry {
                    key_id: "test-key-1".to_string(),
                    secret: "secret123".to_string(),
                    description: Some("Test key".to_string()),
                    enabled: true,
                },
                ApiKeyEntry {
                    key_id: "disabled-key".to_string(),
                    secret: "disabled456".to_string(),
                    description: None,
                    enabled: false,
                },
            ],
            api_keys_file: None,
            allow_anonymous_health: true,
            allow_anonymous_timestamp: false,
        }
    }

    #[tokio::test]
    async fn test_valid_api_key() {
        let auth = Authenticator::new(test_config()).unwrap();

        let result = auth.validate_api_key("secret123").await;
        assert!(result.is_ok());

        let ctx = result.unwrap();
        assert_eq!(ctx.method, AuthMethod::ApiKey);
        assert_eq!(ctx.client_id, "test-key-1");
    }

    #[tokio::test]
    async fn test_invalid_api_key() {
        let auth = Authenticator::new(test_config()).unwrap();

        let result = auth.validate_api_key("wrong-key").await;
        assert!(matches!(result, Err(AuthError::InvalidApiKey)));
    }

    #[tokio::test]
    async fn test_disabled_api_key() {
        let auth = Authenticator::new(test_config()).unwrap();

        let result = auth.validate_api_key("disabled456").await;
        assert!(matches!(result, Err(AuthError::KeyDisabled { .. })));
    }

    #[tokio::test]
    async fn test_anonymous_health() {
        let auth = Authenticator::new(test_config()).unwrap();

        let result = auth.authenticate(None, false, None, true).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, AuthMethod::Anonymous);
    }

    #[tokio::test]
    async fn test_auth_required_for_timestamp() {
        let auth = Authenticator::new(test_config()).unwrap();

        let result = auth.authenticate(None, false, None, false).await;
        assert!(matches!(result, Err(AuthError::MissingCredentials)));
    }

    #[tokio::test]
    async fn test_hybrid_mode() {
        let mut config = test_config();
        config.mode = AuthMode::Hybrid;
        let auth = Authenticator::new(config).unwrap();

        // API key should work
        let result = auth.authenticate(Some("secret123"), false, None, false).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, AuthMethod::ApiKey);

        // mTLS should work
        let result = auth.authenticate(None, true, Some("CN=client"), false).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, AuthMethod::MtlsCertificate);
    }

    #[tokio::test]
    async fn test_disabled_auth() {
        let mut config = test_config();
        config.enabled = false;
        let auth = Authenticator::new(config).unwrap();

        let result = auth.authenticate(None, false, None, false).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, AuthMethod::Anonymous);
    }

    #[test]
    fn test_generate_api_key() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should be URL-safe
        assert!(!key1.contains('+'));
        assert!(!key1.contains('/'));

        // Keys should be reasonable length (32 bytes = ~43 chars base64)
        assert!(key1.len() >= 40);
    }

    #[test]
    fn test_parse_keys_string() {
        let keys = Authenticator::parse_keys_string("key1:secret1,key2:secret2,standalone");
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].key_id, "key1");
        assert_eq!(keys[0].secret, "secret1");
        assert_eq!(keys[1].key_id, "key2");
        assert_eq!(keys[2].secret, "standalone");
    }
}

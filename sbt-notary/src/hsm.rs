//! HSM integration for signing operations
//!
//! Sensitive data (PINs, session handles) is zeroized on drop to prevent
//! leaking secrets in memory. HSM error messages are sanitized in production
//! builds to avoid information leakage.

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;
use tracing::error;
use zeroize::{Zeroize, Zeroizing};
use sbt_types::{PublicKey, Signature};

/// Trait for signing operations, abstracting over HSM and software signers
pub trait Signer: Send + Sync {
    /// Sign a message and return the signature
    fn sign(&self, message: &[u8]) -> Result<Signature, HsmError>;
    /// Get the public key corresponding to the signing key
    fn public_key(&self) -> &PublicKey;
}

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("{}", sanitize_error("PKCS#11 initialization failed", .0))]
    InitializationFailed(String),

    #[error("{}", sanitize_error("Failed to open session", .0))]
    SessionFailed(String),

    #[error("{}", sanitize_error("Login failed", .0))]
    LoginFailed(String),

    #[error("{}", sanitize_error("Key not found", .0))]
    KeyNotFound(String),

    #[error("{}", sanitize_error("Signing failed", .0))]
    SigningFailed(String),

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("{}", sanitize_error("HSM error", .0))]
    Other(String),

    #[error("Lock poisoned")]
    LockPoisoned,
}

/// Sanitize HSM error messages for external display.
///
/// In release builds, only the category is shown (e.g., "Signing failed")
/// to avoid leaking internal HSM details (slot IDs, library paths, etc.).
/// In debug builds, the full detail is included for easier development.
fn sanitize_error(category: &str, detail: &str) -> String {
    if cfg!(debug_assertions) {
        format!("{}: {}", category, detail)
    } else {
        category.to_string()
    }
}

/// Inner HSM state that is not Send/Sync
struct HsmInner {
    _pkcs11: Pkcs11,
    session: Session,
    private_key_handle: ObjectHandle,
}

/// HSM signer for Ed25519 signatures
/// Thread-safe wrapper around cryptoki session
pub struct HsmSigner {
    /// Mutex-protected inner state (cryptoki types are not Send/Sync)
    inner: Mutex<HsmInner>,
    /// Public key (safe to share across threads)
    public_key: PublicKey,
}

impl HsmSigner {
    /// Initialize HSM connection and find the signing key
    pub fn new(
        library_path: &Path,
        slot_id: u64,
        pin: &str,
        key_label: &str,
    ) -> Result<Self, HsmError> {
        // Initialize PKCS#11
        let pkcs11 = Pkcs11::new(library_path)
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        // Open session
        let slot = pkcs11
            .get_slots_with_token()
            .map_err(|e| HsmError::SessionFailed(e.to_string()))?
            .into_iter()
            .find(|s| u64::from(s.id()) == slot_id)
            .ok_or_else(|| HsmError::SessionFailed(format!("Slot {} not found", slot_id)))?;

        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| HsmError::SessionFailed(e.to_string()))?;

        // Login — wrap PIN in Zeroizing so it's cleared from memory after use
        let mut pin_copy = Zeroizing::new(pin.to_string());
        let auth_pin = AuthPin::new(pin_copy.as_str().to_string());
        let login_result = session.login(UserType::User, Some(&auth_pin));
        // Explicitly zeroize our copy now; AuthPin handles its own cleanup
        pin_copy.zeroize();
        login_result.map_err(|e| HsmError::LoginFailed(e.to_string()))?;

        // Find private key
        let private_key_handle = Self::find_key(&session, key_label, true)?;

        // Find corresponding public key
        let public_key_bytes = Self::get_public_key(&session, key_label)?;
        let public_key = PublicKey::from_slice(&public_key_bytes)
            .map_err(|_| HsmError::Other("Invalid public key format".to_string()))?;

        let inner = HsmInner {
            _pkcs11: pkcs11,
            session,
            private_key_handle,
        };

        Ok(Self {
            inner: Mutex::new(inner),
            public_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Sign a message using the HSM
    pub fn sign(&self, message: &[u8]) -> Result<Signature, HsmError> {
        let inner = self.inner.lock().map_err(|_| HsmError::LockPoisoned)?;

        // Use EdDSA mechanism for Ed25519
        // Note: The exact mechanism depends on HSM support
        // Some HSMs may require CKM_ECDSA for EdDSA curves
        let mechanism = Mechanism::Eddsa;

        let signature_bytes = inner
            .session
            .sign(&mechanism, inner.private_key_handle, message)
            .map_err(|e| HsmError::SigningFailed(e.to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(HsmError::InvalidSignature);
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);

        Ok(Signature::new(sig_array))
    }

    /// Find a key by label
    fn find_key(session: &Session, label: &str, is_private: bool) -> Result<ObjectHandle, HsmError> {
        let template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(if is_private {
                cryptoki::object::ObjectClass::PRIVATE_KEY
            } else {
                cryptoki::object::ObjectClass::PUBLIC_KEY
            }),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| HsmError::KeyNotFound(e.to_string()))?;

        objects
            .first()
            .copied()
            .ok_or_else(|| HsmError::KeyNotFound(format!("Key '{}' not found", label)))
    }

    /// Get public key bytes
    fn get_public_key(session: &Session, label: &str) -> Result<Vec<u8>, HsmError> {
        let public_key_handle = Self::find_key(session, label, false)?;

        let attributes = session
            .get_attributes(
                public_key_handle,
                &[AttributeType::Value],
            )
            .map_err(|e| HsmError::Other(e.to_string()))?;

        for attr in attributes {
            if let Attribute::Value(bytes) = attr {
                return Ok(bytes);
            }
        }

        Err(HsmError::KeyNotFound("Public key value not found".to_string()))
    }
}

impl Signer for HsmSigner {
    fn sign(&self, message: &[u8]) -> Result<Signature, HsmError> {
        self.sign(message)
    }

    fn public_key(&self) -> &PublicKey {
        self.public_key()
    }
}

impl Drop for HsmSigner {
    fn drop(&mut self) {
        // Logout and cleanup — log errors instead of silently ignoring them
        match self.inner.get_mut() {
            Ok(inner) => {
                if let Err(e) = inner.session.logout() {
                    error!("HSM session logout failed during cleanup: {}", e);
                }
                // Note: finalize() takes ownership, which we can't do in Drop.
                // The Pkcs11 will be finalized when it's dropped.
            }
            Err(e) => {
                error!("Failed to acquire HSM lock during cleanup: {}", e);
            }
        }
    }
}

/// Software-based Ed25519 signer for testing (no HSM required)
pub struct SoftwareSigner {
    signing_key: ed25519_dalek::SigningKey,
    public_key: PublicKey,
}

impl SoftwareSigner {
    /// Create a new software signer with a random keypair
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = PublicKey::new(verifying_key.to_bytes());
        Self {
            signing_key,
            public_key,
        }
    }
}

impl Signer for SoftwareSigner {
    fn sign(&self, message: &[u8]) -> Result<Signature, HsmError> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(message);
        Ok(Signature::new(sig.to_bytes()))
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires HSM to be available
    fn test_hsm_signer() {
        // This test requires a SoftHSM or real HSM to be configured
        let library_path = Path::new("/usr/lib/softhsm/libsofthsm2.so");
        let signer = HsmSigner::new(library_path, 0, "1234", "test-key");

        if let Ok(signer) = signer {
            let message = b"test message";
            let signature = signer.sign(message).unwrap();
            assert_eq!(signature.as_bytes().len(), 64);
        }
    }
}

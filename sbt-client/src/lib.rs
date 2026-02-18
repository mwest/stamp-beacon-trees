//! SBT Client Library
//!
//! Client library for interacting with SBT (Stamp/Beacon Trees) notary servers

pub mod client;
pub mod grpc;
pub mod storage;
pub mod tls;

pub use client::{SbtClient, RetryConfig, PinMode};
pub use grpc::HealthStatus;
pub use storage::ProofStorage;
pub use tls::{TlsOptions, TlsCertPin, compute_spki_pin, compute_spki_pin_from_pem};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, ClientError>;

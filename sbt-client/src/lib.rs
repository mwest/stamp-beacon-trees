//! Stamp/Beacon Trees Client Library
//!
//! Client library for interacting with Stamp/Beacon Trees notary servers

pub mod client;
pub mod storage;

pub use client::SbtClient;
pub use storage::ProofStorage;

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

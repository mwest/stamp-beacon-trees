//! Error types for Zurvan

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid digest length: expected {expected}, got {actual}")]
    InvalidDigestLength { expected: usize, actual: usize },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid Merkle path")]
    InvalidMerklePath,

    #[error("Merkle path verification failed")]
    MerkleVerificationFailed,

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Hex encoding error: {0}")]
    HexEncoding(#[from] hex::FromHexError),

    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

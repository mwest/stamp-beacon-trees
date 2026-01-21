//! Core types and protocol definitions for SBT (Stamp/Beacon Trees)
//!
//! This crate defines the fundamental data structures and message formats
//! used throughout the SBT timestamping system.

pub mod error;
pub mod messages;
pub mod primitives;

pub use error::{Error, Result};
pub use messages::{
    StampRequest, StampResponse, MerklePath, TimestampProof,
};
pub use primitives::{Digest, Signature, PublicKey, Nonce, Timestamp};

//! Core cryptographic functionality for Stamp/Beacon Trees Stamp/Beacon Trees
//!
//! This crate provides:
//! - Merkle tree construction with per-leaf timing deltas
//! - Cryptographic signature verification
//! - Random nonce generation
//! - Timestamp proof verification

pub mod merkle;
pub mod nonce;
pub mod verify;

pub use merkle::{StampTree, StampTreeBuilder, LeafData};
pub use nonce::NonceGenerator;
pub use verify::{verify_proof, VerificationError};

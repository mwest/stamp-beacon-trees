//! SBT Notary Server
//!
//! The trusted timestamping service that builds stamp/beacon trees
//! and signs them using an HSM.

pub mod auth;
pub mod batch;
pub mod config;
pub mod grpc;
pub mod hsm;
pub mod rate_limit;
pub mod server;
pub mod tls;

#[cfg(feature = "test-util")]
pub mod testutil;

pub use config::NotaryConfig;
pub use server::NotaryServer;

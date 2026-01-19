//! Stamp/Beacon Trees Notary Server
//!
//! The trusted timestamping service that builds stamp/beacon trees
//! and signs them using an HSM.

pub mod config;
pub mod hsm;
pub mod server;
pub mod batch;

pub use config::NotaryConfig;
pub use server::NotaryServer;

//! SBT Notary Server entry point

use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber;
use sbt_notary::{NotaryConfig, NotaryServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("notary.toml")
    };

    // Load configuration
    let config = if config_path.exists() {
        NotaryConfig::from_file(&config_path)?
    } else {
        eprintln!("Configuration file not found: {}", config_path.display());
        eprintln!("Creating default configuration...");
        let config = NotaryConfig::default();
        config.to_file(&config_path)?;
        eprintln!("Default configuration saved to {}", config_path.display());
        eprintln!("Please edit the configuration and set SBT_HSM_PIN environment variable");
        std::process::exit(1);
    };

    // Create and run server
    let server = NotaryServer::new(config)?;
    server.run().await?;

    Ok(())
}

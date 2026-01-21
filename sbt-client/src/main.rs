//! SBT (Stamp/Beacon Trees) CLI client

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use sbt_client::{ProofStorage, SbtClient, TlsOptions};
use sbt_types::Digest;

#[derive(Parser)]
#[command(name = "sbt")]
#[command(about = "SBT (Stamp/Beacon Trees) timestamp client", long_about = None)]
struct Cli {
    /// Server URL (gRPC endpoint)
    /// Use https:// scheme for TLS connections
    #[arg(short, long, default_value = "http://localhost:8080")]
    server: String,

    /// Storage directory
    #[arg(short = 'd', long, default_value = ".sbt")]
    storage_dir: PathBuf,

    /// Path to CA certificate file (PEM) for TLS server verification
    #[arg(long)]
    ca_cert: Option<PathBuf>,

    /// Path to client certificate file (PEM) for mTLS authentication
    #[arg(long)]
    client_cert: Option<PathBuf>,

    /// Path to client private key file (PEM) for mTLS authentication
    #[arg(long)]
    client_key: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Timestamp a file
    Timestamp {
        /// File to timestamp
        file: PathBuf,
    },

    /// Timestamp raw data from stdin
    TimestampStdin,

    /// Verify a timestamp proof
    Verify {
        /// Digest (hex) or file path
        input: String,
    },

    /// List all stored proofs
    List,

    /// Show details of a timestamp proof
    Show {
        /// Digest in hex format
        digest: String,
    },

    /// Export a proof as JSON
    Export {
        /// Digest in hex format
        digest: String,

        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import a proof from JSON
    Import {
        /// Input JSON file
        file: PathBuf,
    },

    /// Get notary's public key
    PublicKey,

    /// Check server health
    Health,
}

fn build_client(cli: &Cli) -> SbtClient {
    // Check if TLS options are provided
    let has_tls = cli.ca_cert.is_some() || cli.server.starts_with("https://");

    if has_tls {
        let mut tls_options = if let Some(ca_cert) = &cli.ca_cert {
            TlsOptions::with_ca_cert(ca_cert.to_string_lossy().to_string())
        } else {
            // Use system roots for https:// URLs without explicit CA cert
            TlsOptions::default()
        };

        // Add client certificate for mTLS if provided
        if let (Some(cert), Some(key)) = (&cli.client_cert, &cli.client_key) {
            tls_options = tls_options.with_client_cert(
                cert.to_string_lossy().to_string(),
                key.to_string_lossy().to_string(),
            );
        }

        SbtClient::with_tls(cli.server.clone(), tls_options)
    } else {
        SbtClient::new(cli.server.clone())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut client = build_client(&cli);
    let storage = ProofStorage::open(&cli.storage_dir)?;

    match cli.command {
        Commands::Timestamp { file } => {
            println!("Timestamping file: {}", file.display());

            let proof = client.timestamp_file(&file).await?;
            let digest = proof.digest;

            storage.store(&digest, &proof)?;

            println!("Timestamp created successfully");
            println!("Digest:    {}", digest);
            println!("Timestamp: {}", proof.leaf_timestamp());
            println!("Notary:    {}", proof.notary_pubkey);
        }

        Commands::TimestampStdin => {
            use std::io::Read;

            println!("Reading data from stdin...");
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;

            let proof = client.timestamp_data(&data).await?;
            let digest = proof.digest;

            storage.store(&digest, &proof)?;

            println!("Timestamp created successfully");
            println!("Digest:    {}", digest);
            println!("Timestamp: {}", proof.leaf_timestamp());
            println!("Notary:    {}", proof.notary_pubkey);
        }

        Commands::Verify { input } => {
            // Try to parse as hex digest first
            let digest = if let Ok(d) = Digest::from_hex(&input) {
                d
            } else {
                // Otherwise treat as file path
                let path = PathBuf::from(&input);
                let data = std::fs::read(&path)?;
                let hash = blake3::hash(&data);
                Digest::new(*hash.as_bytes())
            };

            let proof = storage
                .get(&digest)?
                .ok_or_else(|| anyhow::anyhow!("No proof found for digest: {}", digest))?;

            client.verify(&proof)?;

            println!("Proof verified successfully");
            println!("Digest:    {}", proof.digest);
            println!("Timestamp: {}", proof.leaf_timestamp());
            println!("Notary:    {}", proof.notary_pubkey);
        }

        Commands::List => {
            let proofs = storage.list()?;

            if proofs.is_empty() {
                println!("No stored proofs");
            } else {
                println!("Stored proofs ({})", proofs.len());
                println!();
                for (digest, proof) in proofs {
                    println!("Digest:    {}", digest);
                    println!("Timestamp: {}", proof.leaf_timestamp());
                    println!("Notary:    {}", proof.notary_pubkey);
                    println!();
                }
            }
        }

        Commands::Show { digest } => {
            let digest = Digest::from_hex(&digest)?;
            let proof = storage
                .get(&digest)?
                .ok_or_else(|| anyhow::anyhow!("No proof found for digest: {}", digest))?;

            println!("Timestamp Proof");
            println!("===============");
            println!("Digest:        {}", proof.digest);
            println!("Nonce:         {}", proof.nonce.to_hex());
            println!("Leaf Time:     {}", proof.leaf_timestamp());
            println!("Root Time:     {}", proof.root_timestamp);
            println!("Delta (ns):    {}", proof.delta_nanos);
            println!("Leaf Index:    {}", proof.merkle_path.leaf_index);
            println!("Path Length:   {}", proof.merkle_path.siblings.len());
            println!("Notary Pubkey: {}", proof.notary_pubkey);
            println!("Signature:     {}", proof.signature.to_hex());
        }

        Commands::Export { digest, output } => {
            let digest = Digest::from_hex(&digest)?;
            let json = storage.export_json(&digest)?;

            if let Some(output_path) = output {
                std::fs::write(&output_path, json)?;
                println!("Proof exported to {}", output_path.display());
            } else {
                println!("{}", json);
            }
        }

        Commands::Import { file } => {
            let json = std::fs::read_to_string(&file)?;
            let digest = storage.import_json(&json)?;

            println!("Proof imported successfully");
            println!("Digest: {}", digest);
        }

        Commands::PublicKey => {
            let pubkey = client.get_public_key().await?;
            println!("Notary public key: {}", pubkey);
        }

        Commands::Health => {
            let health = client.health().await?;
            println!("Server Health");
            println!("=============");
            println!("Status:            {}", if health.healthy { "Healthy" } else { "Unhealthy" });
            println!("Uptime:            {} seconds", health.uptime_seconds);
            println!("Timestamps issued: {}", health.timestamps_issued);
        }
    }

    Ok(())
}

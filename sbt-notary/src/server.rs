//! Notary server implementation

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tonic::transport::Server;
use tracing::{info, warn};

use crate::auth::Authenticator;
use crate::batch::{BatchProcessor, BatchRequest};
use crate::config::NotaryConfig;
use crate::grpc::{SbtNotaryService, proto::sbt_notary_server::SbtNotaryServer};
use crate::hsm::HsmSigner;
use crate::rate_limit::RateLimiter;
use crate::tls::load_server_tls_config;
use sbt_types::{StampRequest, StampResponse};

/// The main notary server
pub struct NotaryServer {
    config: NotaryConfig,
    signer: Arc<HsmSigner>,
    request_tx: mpsc::Sender<BatchRequest>,
    rate_limiter: Option<Arc<RateLimiter>>,
    authenticator: Option<Arc<Authenticator>>,
}

impl NotaryServer {
    /// Create a new notary server
    pub fn new(config: NotaryConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing notary server");

        // Initialize HSM signer
        let pin = config
            .hsm
            .pin
            .as_ref()
            .ok_or("HSM PIN not configured")?;

        let signer = HsmSigner::new(
            &config.hsm.pkcs11_library,
            config.hsm.slot_id,
            pin,
            &config.hsm.key_label,
        )?;

        info!("HSM signer initialized, public key: {}", signer.public_key());

        let signer = Arc::new(signer);

        // Create batch processor channel
        let (request_tx, request_rx) = mpsc::channel(config.batch.max_batch_size * 2);

        // Spawn batch processor
        let batch_processor = BatchProcessor::new(
            config.batch.clone(),
            signer.clone(),
            request_rx,
        );

        tokio::spawn(async move {
            batch_processor.run().await;
        });

        // Initialize rate limiter if configured
        let rate_limiter = config.rate_limit.as_ref().map(|rl_config| {
            let limiter = Arc::new(RateLimiter::new(rl_config.clone()));

            // Start background cleanup task
            let cleanup_limiter = limiter.clone();
            cleanup_limiter.start_cleanup_task();

            info!(
                "Rate limiting enabled: {} rps/IP, {} global rps",
                rl_config.per_ip_rps, rl_config.global_rps
            );

            limiter
        });

        // Initialize authenticator if configured
        let authenticator = if let Some(auth_config) = &config.auth {
            let auth = Authenticator::new(auth_config.clone())?;

            if auth.is_enabled() {
                info!(
                    "Authentication enabled (mode: {:?})",
                    auth.mode()
                );
            }

            Some(Arc::new(auth))
        } else {
            info!("Authentication disabled - all requests allowed");
            None
        };

        Ok(Self {
            config,
            signer,
            request_tx,
            rate_limiter,
            authenticator,
        })
    }

    /// Handle a stamp request (internal API for direct calls)
    pub async fn handle_request(
        &self,
        request: StampRequest,
    ) -> Result<StampResponse, Box<dyn std::error::Error>> {
        // Create a oneshot channel for the response
        let (response_tx, response_rx) = oneshot::channel();

        // Send to batch processor
        let batch_request = BatchRequest {
            digest: request.digest,
            client_send_time: request.client_send_time,
            response_tx,
        };

        self.request_tx
            .send(batch_request)
            .await
            .map_err(|_| "Failed to send request to batch processor")?;

        // Wait for response
        let response = response_rx
            .await
            .map_err(|_| "Failed to receive response from batch processor")?;

        Ok(response)
    }

    /// Get the notary's public key
    pub fn public_key(&self) -> &sbt_types::PublicKey {
        self.signer.public_key()
    }

    /// Run the gRPC server
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = format!("{}:{}", self.config.server.host, self.config.server.port)
            .parse()?;

        // Create the gRPC service with rate limiting and/or authentication
        let service = if let Some(auth) = &self.authenticator {
            SbtNotaryService::with_auth(
                self.request_tx.clone(),
                self.signer.clone(),
                self.rate_limiter.clone(),
                auth.clone(),
            )
        } else if let Some(limiter) = &self.rate_limiter {
            SbtNotaryService::with_rate_limiter(
                self.request_tx.clone(),
                self.signer.clone(),
                limiter.clone(),
            )
        } else {
            SbtNotaryService::new(self.request_tx.clone(), self.signer.clone())
        };
        let sbt_service = SbtNotaryServer::new(service);

        // Check if TLS is configured
        if let Some(tls_config) = &self.config.tls {
            info!("Starting gRPC server with TLS on {}", addr);
            info!("Public key: {}", self.public_key());

            if tls_config.ca_cert_path.is_some() {
                info!("mTLS enabled - client certificates will be verified");
            }

            let server_tls_config = load_server_tls_config(tls_config)?;

            Server::builder()
                .tls_config(server_tls_config)?
                .add_service(sbt_service)
                .serve_with_shutdown(addr, async {
                    tokio::signal::ctrl_c().await.ok();
                    info!("Shutting down notary server");
                })
                .await?;
        } else {
            warn!("TLS is disabled - connections are not encrypted!");
            info!("Starting gRPC server (no TLS) on {}", addr);
            info!("Public key: {}", self.public_key());

            Server::builder()
                .add_service(sbt_service)
                .serve_with_shutdown(addr, async {
                    tokio::signal::ctrl_c().await.ok();
                    info!("Shutting down notary server");
                })
                .await?;
        }

        Ok(())
    }
}

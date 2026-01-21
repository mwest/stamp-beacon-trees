//! Notary server implementation

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tonic::transport::Server;
use tracing::info;

use crate::batch::{BatchProcessor, BatchRequest};
use crate::config::NotaryConfig;
use crate::grpc::{SbtNotaryService, proto::sbt_notary_server::SbtNotaryServer};
use crate::hsm::HsmSigner;
use sbt_types::{StampRequest, StampResponse};

/// The main notary server
pub struct NotaryServer {
    config: NotaryConfig,
    signer: Arc<HsmSigner>,
    request_tx: mpsc::Sender<BatchRequest>,
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

        Ok(Self {
            config,
            signer,
            request_tx,
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

        info!("Starting gRPC server on {}", addr);
        info!("Public key: {}", self.public_key());

        // Create the gRPC service
        let service = SbtNotaryService::new(self.request_tx.clone(), self.signer.clone());

        // Build and run the server
        Server::builder()
            .add_service(SbtNotaryServer::new(service))
            .serve_with_shutdown(addr, async {
                tokio::signal::ctrl_c().await.ok();
                info!("Shutting down notary server");
            })
            .await?;

        Ok(())
    }
}

//! Test utilities for running an in-process notary server without HSM.
//!
//! Enabled via the `test-util` feature flag.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::transport::Server;

use crate::batch::BatchProcessor;
use crate::config::BatchConfig;
use crate::grpc::{SbtNotaryService, proto::sbt_notary_server::SbtNotaryServer};
use crate::hsm::{Signer, SoftwareSigner};
use sbt_types::PublicKey;

/// A test notary server that uses a software signer (no HSM required).
///
/// Binds to a random port on localhost and provides the address for client connections.
pub struct TestServer {
    /// The address the server is listening on
    addr: SocketAddr,
    /// The notary's public key
    public_key: PublicKey,
    /// Shutdown signal sender
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl TestServer {
    /// Start a test server on a random port.
    ///
    /// Returns immediately after the server is ready to accept connections.
    pub async fn start() -> Self {
        Self::start_with_batch_config(BatchConfig {
            max_batch_size: 100,
            max_wait_ms: 50,
            batch_interval_ms: 50,
        })
        .await
    }

    /// Start a test server with custom batch configuration.
    pub async fn start_with_batch_config(batch_config: BatchConfig) -> Self {
        let signer = Arc::new(SoftwareSigner::generate());
        let public_key = signer.public_key().clone();

        // Create batch processor channel
        let (request_tx, request_rx) = mpsc::channel(batch_config.max_batch_size * 2);

        // Spawn batch processor
        let batch_processor = BatchProcessor::new(
            batch_config,
            signer.clone(),
            request_rx,
        );
        tokio::spawn(async move {
            batch_processor.run().await;
        });

        // Create gRPC service (no auth, no rate limiting for tests)
        let service = SbtNotaryService::new(request_tx, signer);
        let sbt_service = SbtNotaryServer::new(service);

        // Bind to a random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().expect("Failed to get local address");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Convert TcpListener to the stream type tonic expects
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        tokio::spawn(async move {
            Server::builder()
                .add_service(sbt_service)
                .serve_with_incoming_shutdown(incoming, async {
                    shutdown_rx.await.ok();
                })
                .await
                .expect("Test server failed");
        });

        // Give the server a moment to start accepting connections
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        Self {
            addr,
            public_key,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Get the server's listening address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get the server URL suitable for client connection (e.g., "http://127.0.0.1:12345")
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Get the notary's public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Shut down the test server
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

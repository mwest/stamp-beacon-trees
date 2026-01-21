//! Batch processing of timestamp requests

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, info, warn};
use sbt_core::{LeafData, NonceGenerator, StampTreeBuilder};
use sbt_types::{Digest, StampResponse, Timestamp, TimestampProof};

use crate::config::BatchConfig;
use crate::hsm::HsmSigner;

/// A single timestamp request in the batch
pub struct BatchRequest {
    pub digest: Digest,
    pub client_send_time: Timestamp,
    pub response_tx: oneshot::Sender<StampResponse>,
}

/// Batch processor that accumulates requests and builds stamp trees
pub struct BatchProcessor {
    config: BatchConfig,
    signer: Arc<HsmSigner>,
    nonce_gen: Arc<RwLock<NonceGenerator>>,
    request_rx: mpsc::Receiver<BatchRequest>,
    pending_requests: Vec<BatchRequest>,
}

impl BatchProcessor {
    pub fn new(
        config: BatchConfig,
        signer: Arc<HsmSigner>,
        request_rx: mpsc::Receiver<BatchRequest>,
    ) -> Self {
        let capacity = config.max_batch_size;
        Self {
            config,
            signer,
            nonce_gen: Arc::new(RwLock::new(NonceGenerator::new())),
            request_rx,
            pending_requests: Vec::with_capacity(capacity),
        }
    }

    /// Run the batch processor loop
    pub async fn run(mut self) {
        info!("Batch processor started");

        let mut interval = tokio::time::interval(
            std::time::Duration::from_millis(self.config.batch_interval_ms)
        );

        loop {
            tokio::select! {
                // Wait for batch interval
                _ = interval.tick() => {
                    if !self.pending_requests.is_empty() {
                        self.process_batch().await;
                    }
                }

                // Receive new request
                Some(request) = self.request_rx.recv() => {
                    self.pending_requests.push(request);

                    // Process if batch is full
                    if self.pending_requests.len() >= self.config.max_batch_size {
                        self.process_batch().await;
                    }
                }

                // Channel closed
                else => {
                    info!("Request channel closed, processing final batch");
                    if !self.pending_requests.is_empty() {
                        self.process_batch().await;
                    }
                    break;
                }
            }
        }

        info!("Batch processor stopped");
    }

    /// Process the current batch of requests
    async fn process_batch(&mut self) {
        let batch_size = self.pending_requests.len();
        debug!("Processing batch of {} requests", batch_size);

        if batch_size == 0 {
            return;
        }

        // Record the root timestamp (current time)
        let root_timestamp = Timestamp::now();

        // Build the stamp tree
        let mut builder = StampTreeBuilder::new();
        let mut nonce_gen = self.nonce_gen.write().await;

        // Create leaves with timing deltas
        // For now, we assign deltas based on order received
        // In a production system, actual processing times would be measured
        let start_time = root_timestamp.add_nanos(-(batch_size as i64 / 2) * 1000);

        for (i, request) in self.pending_requests.iter().enumerate() {
            let nonce = nonce_gen.generate();
            let delta_nanos = (i as i64 * 1000) - (batch_size as i64 / 2 * 1000);

            builder.add_leaf(LeafData {
                digest: request.digest.clone(),
                nonce,
                delta_nanos,
            });
        }

        drop(nonce_gen);

        let tree = builder.build(root_timestamp);
        info!(
            "Built stamp tree with {} leaves, root timestamp: {}",
            tree.leaf_count(),
            root_timestamp
        );

        // Sign the tree root
        let sign_message = sbt_types::messages::build_sign_message(
            tree.root_hash(),
            &root_timestamp,
        );

        let signature = match self.signer.sign(&sign_message) {
            Ok(sig) => sig,
            Err(e) => {
                warn!("Failed to sign tree root: {}", e);
                // Send errors to all pending requests
                for request in self.pending_requests.drain(..) {
                    let _ = request.response_tx.send(create_error_response());
                }
                return;
            }
        };

        // Generate proofs and send responses
        let notary_send_time = Timestamp::now();

        for (i, request) in self.pending_requests.drain(..).enumerate() {
            let leaf = tree.get_leaf(i).expect("Leaf must exist");
            let merkle_path = tree.generate_path(i).expect("Path must exist");

            let proof = TimestampProof {
                digest: leaf.digest.clone(),
                nonce: leaf.nonce.clone(),
                merkle_path,
                delta_nanos: leaf.delta_nanos,
                root_timestamp,
                signature: signature.clone(),
                notary_pubkey: self.signer.public_key().clone(),
            };

            let response = StampResponse {
                version: 1,
                proof,
                notary_send_time,
            };

            // Send response (ignore if receiver dropped)
            let _ = request.response_tx.send(response);
        }

        info!("Batch processing complete, sent {} responses", batch_size);
    }
}

fn create_error_response() -> StampResponse {
    // Create a minimal error response
    // In practice, you'd want a proper error type
    StampResponse {
        version: 1,
        proof: TimestampProof {
            digest: Digest::new([0u8; 32]),
            nonce: sbt_types::Nonce::new([0u8; 32]),
            merkle_path: sbt_types::messages::MerklePath {
                leaf_index: 0,
                siblings: vec![],
            },
            delta_nanos: 0,
            root_timestamp: Timestamp::now(),
            signature: sbt_types::Signature::new([0u8; 64]),
            notary_pubkey: sbt_types::PublicKey::new([0u8; 32]),
        },
        notary_send_time: Timestamp::now(),
    }
}

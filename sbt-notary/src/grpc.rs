//! gRPC service implementation for the SBT Notary

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};
use tracing::{debug, info};

use crate::auth::{AuthError, Authenticator};
use crate::batch::BatchRequest;
use crate::hsm::HsmSigner;
use crate::rate_limit::{RateLimiter, RateLimitError};
use sbt_types::{Digest, Nonce, PublicKey, Signature, Timestamp as SbtTimestamp};
use sbt_types::messages::{MerklePath, MerkleNode, TimestampProof};

// Include the generated protobuf code
pub mod proto {
    tonic::include_proto!("sbt");
}

use proto::sbt_notary_server::SbtNotary;
use proto::{
    HealthRequest, HealthResponse, PublicKeyRequest, PublicKeyResponse,
    StampRequest, StampResponse, health_response::Status as HealthStatus,
};

/// The API key header name
pub const API_KEY_HEADER: &str = "x-api-key";

/// The gRPC service implementation
pub struct SbtNotaryService {
    request_tx: mpsc::Sender<BatchRequest>,
    signer: Arc<HsmSigner>,
    rate_limiter: Option<Arc<RateLimiter>>,
    authenticator: Option<Arc<Authenticator>>,
    start_time: Instant,
    timestamps_issued: AtomicU64,
}

impl SbtNotaryService {
    /// Create a new gRPC service
    pub fn new(request_tx: mpsc::Sender<BatchRequest>, signer: Arc<HsmSigner>) -> Self {
        Self {
            request_tx,
            signer,
            rate_limiter: None,
            authenticator: None,
            start_time: Instant::now(),
            timestamps_issued: AtomicU64::new(0),
        }
    }

    /// Create a new gRPC service with rate limiting
    pub fn with_rate_limiter(
        request_tx: mpsc::Sender<BatchRequest>,
        signer: Arc<HsmSigner>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            request_tx,
            signer,
            rate_limiter: Some(rate_limiter),
            authenticator: None,
            start_time: Instant::now(),
            timestamps_issued: AtomicU64::new(0),
        }
    }

    /// Create a new gRPC service with rate limiting and authentication
    pub fn with_auth(
        request_tx: mpsc::Sender<BatchRequest>,
        signer: Arc<HsmSigner>,
        rate_limiter: Option<Arc<RateLimiter>>,
        authenticator: Arc<Authenticator>,
    ) -> Self {
        Self {
            request_tx,
            signer,
            rate_limiter,
            authenticator: Some(authenticator),
            start_time: Instant::now(),
            timestamps_issued: AtomicU64::new(0),
        }
    }

    /// Extract client IP from request metadata
    fn extract_client_ip<T>(&self, request: &Request<T>) -> Option<IpAddr> {
        // Try to get from x-forwarded-for header (for reverse proxies)
        if let Some(forwarded) = request.metadata().get("x-forwarded-for") {
            if let Ok(s) = forwarded.to_str() {
                // Take the first IP in the chain (original client)
                if let Some(ip_str) = s.split(',').next() {
                    if let Ok(ip) = ip_str.trim().parse() {
                        return Some(ip);
                    }
                }
            }
        }

        // Try to get from x-real-ip header
        if let Some(real_ip) = request.metadata().get("x-real-ip") {
            if let Ok(s) = real_ip.to_str() {
                if let Ok(ip) = s.parse() {
                    return Some(ip);
                }
            }
        }

        // Fall back to remote address from connection
        request.remote_addr().map(|addr| addr.ip())
    }

    /// Check rate limits for a request
    async fn check_rate_limits<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(limiter) = &self.rate_limiter {
            let client_ip = self.extract_client_ip(request)
                .unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

            limiter.check_rate_limit(client_ip).await.map_err(rate_limit_to_status)?;
        }
        Ok(())
    }

    /// Check request size limits
    fn check_request_size(&self, size: usize) -> Result<(), Status> {
        if let Some(limiter) = &self.rate_limiter {
            limiter.check_request_size(size).map_err(rate_limit_to_status)?;
        }
        Ok(())
    }

    /// Extract API key from request metadata
    fn extract_api_key<T>(&self, request: &Request<T>) -> Option<String> {
        request
            .metadata()
            .get(API_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Check if the request has a valid mTLS client certificate
    /// Note: In tonic, mTLS verification happens at the TLS layer.
    /// If we get here with mTLS configured, the client was already verified.
    fn has_client_certificate<T>(&self, _request: &Request<T>) -> bool {
        // TODO: When tonic supports extracting client cert info,
        // we can check for specific cert attributes here.
        // For now, if mTLS is configured at the TLS layer, clients
        // reaching this point have already been verified.
        false // Conservatively return false until we can extract cert info
    }

    /// Authenticate a request for the timestamp endpoint
    async fn authenticate_timestamp<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(auth) = &self.authenticator {
            let api_key = self.extract_api_key(request);
            let has_cert = self.has_client_certificate(request);

            auth.authenticate(
                api_key.as_deref(),
                has_cert,
                None,
                false, // not a health endpoint
            )
            .await
            .map_err(auth_error_to_status)?;
        }
        Ok(())
    }

    /// Authenticate a request for health/public key endpoints
    async fn authenticate_health<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(auth) = &self.authenticator {
            let api_key = self.extract_api_key(request);
            let has_cert = self.has_client_certificate(request);

            auth.authenticate(
                api_key.as_deref(),
                has_cert,
                None,
                true, // health endpoint
            )
            .await
            .map_err(auth_error_to_status)?;
        }
        Ok(())
    }
}

/// Convert rate limit error to gRPC status
fn rate_limit_to_status(err: RateLimitError) -> Status {
    match err {
        RateLimitError::GlobalLimitExceeded | RateLimitError::PerIpLimitExceeded => {
            Status::resource_exhausted(err.to_string())
        }
        RateLimitError::RequestTooLarge { .. } => {
            Status::invalid_argument(err.to_string())
        }
    }
}

/// Convert authentication error to gRPC status
fn auth_error_to_status(err: AuthError) -> Status {
    match err {
        AuthError::MissingCredentials | AuthError::AuthenticationRequired => {
            Status::unauthenticated(err.to_string())
        }
        AuthError::InvalidApiKey | AuthError::KeyDisabled { .. } => {
            Status::unauthenticated(err.to_string())
        }
        AuthError::MtlsRequired => {
            Status::unauthenticated(err.to_string())
        }
    }
}

#[tonic::async_trait]
impl SbtNotary for SbtNotaryService {
    async fn timestamp(
        &self,
        request: Request<StampRequest>,
    ) -> Result<Response<StampResponse>, Status> {
        // Check authentication first
        self.authenticate_timestamp(&request).await?;

        // Check rate limits
        self.check_rate_limits(&request).await?;

        let req = request.into_inner();

        // Check request size (approximate based on digest field)
        self.check_request_size(req.digest.len())?;

        // Validate version
        if req.version != 1 {
            return Err(Status::invalid_argument(format!(
                "Unsupported protocol version: {}, expected 1",
                req.version
            )));
        }

        // Validate digest length
        if req.digest.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "Invalid digest length: {}, expected 32 bytes",
                req.digest.len()
            )));
        }

        // Convert protobuf types to internal types
        let digest = Digest::from_slice(&req.digest)
            .map_err(|e| Status::invalid_argument(format!("Invalid digest: {}", e)))?;

        let client_send_time = req
            .client_send_time
            .map(|ts| SbtTimestamp::new(ts.seconds, ts.nanos).unwrap_or_else(|_| SbtTimestamp::now()))
            .unwrap_or_else(SbtTimestamp::now);

        debug!("Received timestamp request for digest: {:?}", digest);

        // Create response channel
        let (response_tx, response_rx) = oneshot::channel();

        // Submit to batch processor
        let batch_request = BatchRequest {
            digest,
            client_send_time,
            response_tx,
        };

        self.request_tx
            .send(batch_request)
            .await
            .map_err(|_| Status::internal("Failed to submit request to batch processor"))?;

        // Wait for response
        let response = response_rx
            .await
            .map_err(|_| Status::internal("Failed to receive response from batch processor"))?;

        // Increment counter
        self.timestamps_issued.fetch_add(1, Ordering::Relaxed);

        // Convert response to protobuf
        let proto_response = stamp_response_to_proto(&response);

        Ok(Response::new(proto_response))
    }

    async fn get_public_key(
        &self,
        request: Request<PublicKeyRequest>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        // Check authentication (allows anonymous by default)
        self.authenticate_health(&request).await?;

        let pubkey = self.signer.public_key();

        info!("Public key requested");

        Ok(Response::new(PublicKeyResponse {
            public_key: pubkey.as_bytes().to_vec(),
            notary_id: String::new(), // Could be configured
        }))
    }

    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        // Check authentication (allows anonymous by default)
        self.authenticate_health(&request).await?;

        let uptime = self.start_time.elapsed().as_secs();
        let timestamps_issued = self.timestamps_issued.load(Ordering::Relaxed);

        Ok(Response::new(HealthResponse {
            status: HealthStatus::Healthy.into(),
            uptime_seconds: uptime,
            timestamps_issued,
        }))
    }
}

/// Convert internal StampResponse to protobuf StampResponse
fn stamp_response_to_proto(response: &sbt_types::StampResponse) -> StampResponse {
    StampResponse {
        version: response.version,
        proof: Some(timestamp_proof_to_proto(&response.proof)),
        notary_send_time: Some(timestamp_to_proto(&response.notary_send_time)),
    }
}

/// Convert internal TimestampProof to protobuf TimestampProof
fn timestamp_proof_to_proto(proof: &TimestampProof) -> proto::TimestampProof {
    proto::TimestampProof {
        digest: proof.digest.as_bytes().to_vec(),
        nonce: proof.nonce.as_bytes().to_vec(),
        merkle_path: Some(merkle_path_to_proto(&proof.merkle_path)),
        delta_nanos: proof.delta_nanos,
        root_timestamp: Some(timestamp_to_proto(&proof.root_timestamp)),
        signature: proof.signature.as_bytes().to_vec(),
        notary_pubkey: proof.notary_pubkey.as_bytes().to_vec(),
    }
}

/// Convert internal MerklePath to protobuf MerklePath
fn merkle_path_to_proto(path: &MerklePath) -> proto::MerklePath {
    proto::MerklePath {
        leaf_index: path.leaf_index,
        siblings: path
            .siblings
            .iter()
            .map(|node| proto::MerkleNode {
                hash: node.hash.as_bytes().to_vec(),
                is_left: node.is_left,
            })
            .collect(),
    }
}

/// Convert internal Timestamp to protobuf Timestamp
fn timestamp_to_proto(ts: &SbtTimestamp) -> proto::Timestamp {
    proto::Timestamp {
        seconds: ts.seconds,
        nanos: ts.nanos,
    }
}

// Conversion functions from protobuf to internal types (for client use)

/// Convert protobuf StampResponse to internal StampResponse
pub fn proto_to_stamp_response(response: StampResponse) -> Result<sbt_types::StampResponse, Status> {
    let proof = response
        .proof
        .ok_or_else(|| Status::internal("Missing proof in response"))?;

    let notary_send_time = response
        .notary_send_time
        .ok_or_else(|| Status::internal("Missing notary_send_time in response"))?;

    Ok(sbt_types::StampResponse {
        version: response.version,
        proof: proto_to_timestamp_proof(proof)?,
        notary_send_time: proto_to_timestamp(notary_send_time)?,
    })
}

/// Convert protobuf TimestampProof to internal TimestampProof
pub fn proto_to_timestamp_proof(proof: proto::TimestampProof) -> Result<TimestampProof, Status> {
    let digest = Digest::from_slice(&proof.digest)
        .map_err(|e| Status::internal(format!("Invalid digest: {}", e)))?;

    let nonce = Nonce::from_slice(&proof.nonce)
        .map_err(|e| Status::internal(format!("Invalid nonce: {}", e)))?;

    let merkle_path = proof
        .merkle_path
        .ok_or_else(|| Status::internal("Missing merkle_path"))?;

    let root_timestamp = proof
        .root_timestamp
        .ok_or_else(|| Status::internal("Missing root_timestamp"))?;

    let signature = Signature::from_slice(&proof.signature)
        .map_err(|e| Status::internal(format!("Invalid signature: {}", e)))?;

    let notary_pubkey = PublicKey::from_slice(&proof.notary_pubkey)
        .map_err(|e| Status::internal(format!("Invalid public key: {}", e)))?;

    Ok(TimestampProof {
        digest,
        nonce,
        merkle_path: proto_to_merkle_path(merkle_path)?,
        delta_nanos: proof.delta_nanos,
        root_timestamp: proto_to_timestamp(root_timestamp)?,
        signature,
        notary_pubkey,
    })
}

/// Convert protobuf MerklePath to internal MerklePath
fn proto_to_merkle_path(path: proto::MerklePath) -> Result<MerklePath, Status> {
    let siblings = path
        .siblings
        .into_iter()
        .map(|node| {
            let hash = Digest::from_slice(&node.hash)
                .map_err(|e| Status::internal(format!("Invalid hash in merkle path: {}", e)))?;
            Ok(MerkleNode {
                hash,
                is_left: node.is_left,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;

    Ok(MerklePath {
        leaf_index: path.leaf_index,
        siblings,
    })
}

/// Convert protobuf Timestamp to internal Timestamp
fn proto_to_timestamp(ts: proto::Timestamp) -> Result<SbtTimestamp, Status> {
    SbtTimestamp::new(ts.seconds, ts.nanos)
        .map_err(|e| Status::internal(format!("Invalid timestamp: {}", e)))
}

//! gRPC client implementation for communicating with SBT notary servers

use tonic::transport::Channel;

use sbt_types::{Digest, Nonce, PublicKey, Signature, Timestamp as SbtTimestamp};
use sbt_types::messages::{MerklePath, MerkleNode, TimestampProof, StampResponse};

use crate::{ClientError, Result};

// Include the generated protobuf code
pub mod proto {
    tonic::include_proto!("sbt");
}

use proto::sbt_notary_client::SbtNotaryClient;
use proto::{StampRequest, PublicKeyRequest, HealthRequest};

/// gRPC client for the SBT Notary service
pub struct GrpcClient {
    client: SbtNotaryClient<Channel>,
}

impl GrpcClient {
    /// Connect to a notary server
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let client = SbtNotaryClient::connect(endpoint.to_string())
            .await
            .map_err(|e| ClientError::Network(format!("Failed to connect: {}", e)))?;

        Ok(Self { client })
    }

    /// Submit a digest for timestamping
    pub async fn timestamp(&mut self, digest: &Digest) -> Result<StampResponse> {
        let client_send_time = SbtTimestamp::now();

        let request = StampRequest {
            version: 1,
            digest: digest.as_bytes().to_vec(),
            client_send_time: Some(timestamp_to_proto(&client_send_time)),
        };

        let response = self
            .client
            .timestamp(request)
            .await
            .map_err(|e| ClientError::Network(format!("Timestamp request failed: {}", e)))?
            .into_inner();

        proto_to_stamp_response(response)
    }

    /// Get the notary's public key
    pub async fn get_public_key(&mut self) -> Result<PublicKey> {
        let response = self
            .client
            .get_public_key(PublicKeyRequest {})
            .await
            .map_err(|e| ClientError::Network(format!("GetPublicKey request failed: {}", e)))?
            .into_inner();

        PublicKey::from_slice(&response.public_key)
            .map_err(|e| ClientError::InvalidProof)
    }

    /// Check server health
    pub async fn health(&mut self) -> Result<HealthStatus> {
        let response = self
            .client
            .health(HealthRequest {})
            .await
            .map_err(|e| ClientError::Network(format!("Health check failed: {}", e)))?
            .into_inner();

        Ok(HealthStatus {
            healthy: response.status == proto::health_response::Status::Healthy as i32,
            uptime_seconds: response.uptime_seconds,
            timestamps_issued: response.timestamps_issued,
        })
    }
}

/// Server health status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub healthy: bool,
    pub uptime_seconds: u64,
    pub timestamps_issued: u64,
}

// Conversion functions from protobuf to internal types

/// Convert protobuf StampResponse to internal StampResponse
fn proto_to_stamp_response(response: proto::StampResponse) -> Result<StampResponse> {
    let proof = response
        .proof
        .ok_or_else(|| ClientError::InvalidProof)?;

    let notary_send_time = response
        .notary_send_time
        .ok_or_else(|| ClientError::InvalidProof)?;

    Ok(StampResponse {
        version: response.version,
        proof: proto_to_timestamp_proof(proof)?,
        notary_send_time: proto_to_timestamp(notary_send_time)?,
    })
}

/// Convert protobuf TimestampProof to internal TimestampProof
fn proto_to_timestamp_proof(proof: proto::TimestampProof) -> Result<TimestampProof> {
    let digest = Digest::from_slice(&proof.digest)
        .map_err(|_| ClientError::InvalidProof)?;

    let nonce = Nonce::from_slice(&proof.nonce)
        .map_err(|_| ClientError::InvalidProof)?;

    let merkle_path = proof
        .merkle_path
        .ok_or_else(|| ClientError::InvalidProof)?;

    let root_timestamp = proof
        .root_timestamp
        .ok_or_else(|| ClientError::InvalidProof)?;

    let signature = Signature::from_slice(&proof.signature)
        .map_err(|_| ClientError::InvalidProof)?;

    let notary_pubkey = PublicKey::from_slice(&proof.notary_pubkey)
        .map_err(|_| ClientError::InvalidProof)?;

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
fn proto_to_merkle_path(path: proto::MerklePath) -> Result<MerklePath> {
    let siblings = path
        .siblings
        .into_iter()
        .map(|node| {
            let hash = Digest::from_slice(&node.hash)
                .map_err(|_| ClientError::InvalidProof)?;
            Ok(MerkleNode {
                hash,
                is_left: node.is_left,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(MerklePath {
        leaf_index: path.leaf_index,
        siblings,
    })
}

/// Convert protobuf Timestamp to internal Timestamp
fn proto_to_timestamp(ts: proto::Timestamp) -> Result<SbtTimestamp> {
    SbtTimestamp::new(ts.seconds, ts.nanos)
        .map_err(|_| ClientError::InvalidProof)
}

/// Convert internal Timestamp to protobuf Timestamp
fn timestamp_to_proto(ts: &SbtTimestamp) -> proto::Timestamp {
    proto::Timestamp {
        seconds: ts.seconds,
        nanos: ts.nanos,
    }
}

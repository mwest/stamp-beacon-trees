//! gRPC client implementation for communicating with SBT notary servers

use std::sync::Arc;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::metadata::MetadataValue;
use tonic::Request;

use sbt_types::{Digest, Nonce, PublicKey, Signature, Timestamp as SbtTimestamp};
use sbt_types::messages::{MerklePath, MerkleNode, TimestampProof, StampResponse};

use crate::tls::{TlsOptions, load_client_tls_config, build_pinned_rustls_config};
use crate::{ClientError, Result};

// Include the generated protobuf code
pub mod proto {
    tonic::include_proto!("sbt");
}

use proto::sbt_notary_client::SbtNotaryClient;
use proto::{StampRequest, PublicKeyRequest, HealthRequest};

/// The API key header name (must match server)
const API_KEY_HEADER: &str = "x-api-key";

/// gRPC client for the SBT Notary service
pub struct GrpcClient {
    client: SbtNotaryClient<Channel>,
    /// API key for authentication
    api_key: Option<String>,
}

impl GrpcClient {
    /// Connect to a notary server (no TLS)
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let client = SbtNotaryClient::connect(endpoint.to_string())
            .await
            .map_err(|e| ClientError::Network(format!("Failed to connect: {}", e)))?;

        Ok(Self { client, api_key: None })
    }

    /// Connect to a notary server with TLS
    pub async fn connect_with_tls(endpoint: &str, tls_options: &TlsOptions) -> Result<Self> {
        if tls_options.has_cert_pin() {
            // Use custom rustls config with SPKI pinning verifier
            Self::connect_with_pinned_tls(endpoint, tls_options).await
        } else {
            // Standard tonic TLS path (no cert pinning)
            let tls_config = load_client_tls_config(tls_options)
                .map_err(|e| ClientError::Network(format!("Failed to load TLS config: {}", e)))?;

            let channel = Endpoint::from_shared(endpoint.to_string())
                .map_err(|e| ClientError::Network(format!("Invalid endpoint: {}", e)))?
                .tls_config(tls_config)
                .map_err(|e| ClientError::Network(format!("Failed to configure TLS: {}", e)))?
                .connect()
                .await
                .map_err(|e| ClientError::Network(format!("Failed to connect with TLS: {}", e)))?;

            let client = SbtNotaryClient::new(channel);

            Ok(Self { client, api_key: None })
        }
    }

    /// Connect with TLS using a custom rustls config that verifies SPKI pins.
    ///
    /// This bypasses tonic's built-in TLS and instead uses a custom tower::Service
    /// connector with our `SpkiPinVerifier` rustls config, connected via
    /// `Endpoint::connect_with_connector`.
    async fn connect_with_pinned_tls(endpoint: &str, tls_options: &TlsOptions) -> Result<Self> {
        let rustls_config = build_pinned_rustls_config(tls_options)
            .map_err(|e| ClientError::Network(format!("Failed to build pinned TLS config: {}", e)))?;

        // Parse the endpoint URI to extract the server name for TLS SNI
        let uri: Uri = endpoint.parse()
            .map_err(|e| ClientError::Network(format!("Invalid endpoint URI: {}", e)))?;
        let host = uri.host()
            .ok_or_else(|| ClientError::Network("No host in endpoint URI".to_string()))?
            .to_string();

        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));

        let connector = PinnedTlsConnector {
            tls: tls_connector,
            server_name: host,
        };

        // Use http:// scheme so tonic doesn't try to add its own TLS layer.
        // Our custom connector handles TLS transparently.
        let http_endpoint = endpoint.replace("https://", "http://");

        let channel = Endpoint::from_shared(http_endpoint)
            .map_err(|e| ClientError::Network(format!("Invalid endpoint: {}", e)))?
            .connect_with_connector_lazy(connector);

        let client = SbtNotaryClient::new(channel);
        Ok(Self { client, api_key: None })
    }

    /// Set the API key for authentication
    pub fn set_api_key(&mut self, api_key: String) {
        self.api_key = Some(api_key);
    }

    /// Create a request with authentication headers
    fn make_request<T>(&self, inner: T) -> Request<T> {
        let mut request = Request::new(inner);

        if let Some(api_key) = &self.api_key {
            if let Ok(value) = api_key.parse::<MetadataValue<_>>() {
                request.metadata_mut().insert(API_KEY_HEADER, value);
            }
        }

        request
    }

    /// Submit a digest for timestamping
    pub async fn timestamp(&mut self, digest: &Digest) -> Result<StampResponse> {
        let client_send_time = SbtTimestamp::now();

        let inner = StampRequest {
            version: 1,
            digest: digest.as_bytes().to_vec(),
            client_send_time: Some(timestamp_to_proto(&client_send_time)),
        };

        let request = self.make_request(inner);

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
        let request = self.make_request(PublicKeyRequest {});

        let response = self
            .client
            .get_public_key(request)
            .await
            .map_err(|e| ClientError::Network(format!("GetPublicKey request failed: {}", e)))?
            .into_inner();

        PublicKey::from_slice(&response.public_key)
            .map_err(|_| ClientError::InvalidProof)
    }

    /// Check server health
    pub async fn health(&mut self) -> Result<HealthStatus> {
        let request = self.make_request(HealthRequest {});

        let response = self
            .client
            .health(request)
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

/// Custom tower connector that performs TCP + TLS with our pinned rustls config.
///
/// Implements `tower::Service<Uri>` so it can be passed to
/// `Endpoint::connect_with_connector()`.
#[derive(Clone)]
struct PinnedTlsConnector {
    tls: tokio_rustls::TlsConnector,
    server_name: String,
}

impl tower::Service<Uri> for PinnedTlsConnector {
    type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls = self.tls.clone();
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let host = uri.host().unwrap_or(&server_name);
            let port = uri.port_u16().unwrap_or(443);
            let addr = format!("{}:{}", host, port);

            // TCP connect
            let tcp = tokio::net::TcpStream::connect(&addr).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(e)
                })?;

            // Build TLS server name — handle both IP addresses and DNS names.
            // If the host parses as an IP address, use IpAddress variant;
            // otherwise use DnsName.
            let domain: rustls::pki_types::ServerName<'static> =
                if let Ok(ip) = server_name.parse::<std::net::IpAddr>() {
                    rustls::pki_types::ServerName::IpAddress(
                        rustls::pki_types::IpAddr::from(ip),
                    )
                } else {
                    rustls::pki_types::ServerName::try_from(server_name.as_str())
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
                        })?
                        .to_owned()
                };

            // TLS handshake with our custom rustls config (including SPKI pin check)
            let tls_stream = tls.connect(domain, tcp).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(e)
                })?;

            Ok(hyper_util::rt::TokioIo::new(tls_stream))
        })
    }
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

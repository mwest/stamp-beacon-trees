# SBT (Stamp/Beacon Trees) TODO List

## Recently Completed ✅

- [x] **Implemented authentication** - API key and mTLS authentication with configurable modes. See `sbt-notary/src/auth.rs` and `[auth]` config section in `notary.example.toml`.
- [x] **Implemented rate limiting** - Token bucket rate limiter with per-IP and global limits. See `sbt-notary/src/rate_limit.rs` and `[rate_limit]` config section in `notary.example.toml`.
- [x] **Implemented TLS support** - Server and client TLS with optional mTLS. See `sbt-notary/src/tls.rs`, `sbt-client/src/tls.rs`, and CLI `--ca-cert`, `--client-cert`, `--client-key` options.
- [x] **Implemented gRPC network protocol** - Full client/server communication using tonic/prost. See `proto/sbt.proto`, `sbt-notary/src/grpc.rs`, `sbt-client/src/grpc.rs`.
- [x] **Fixed critical Merkle path verification bug** - The comparison was checking `computed_root != computed_root` (always false). Fixed in `sbt-core/src/verify.rs`.
- [x] **Added domain separation to signatures** - Added `SBT-v1:` prefix to prevent cross-protocol signature reuse attacks. See `sbt-types/src/messages.rs`.
- [x] **Made `Digest` type `Copy`** - Optimized by adding `Copy` derive and removing unnecessary `.clone()` calls.
- [x] **Improved unsafe unwrap() handling** - Replaced bare `unwrap()` with `while let` pattern and `expect()` with messages in `sbt-core/src/merkle.rs`.
- [x] **Added thread safety documentation** - Documented `NonceGenerator` thread safety requirements in `sbt-core/src/nonce.rs`.
- [x] **Fixed Merkle path generation for odd-sized trees** - `generate_path()` was missing the duplicated sibling for odd nodes at level boundaries, causing verification failures. Fixed in `sbt-core/src/merkle.rs`.
- [x] **Fixed test compilation errors** - Added missing `Hash` derive on `Nonce` type, fixed `Signature::new(*sig.to_bytes())` dereference errors in `sbt-core/src/verify.rs`, added missing `tempfile` dev-dependency to `sbt-client`.
- [x] **Cleaned up all compiler warnings** - Removed unused imports, variables, and dead code across `sbt-client`, `sbt-notary`, and `sbt-core`.
- [x] **Added Signer trait abstraction** - Extracted `Signer` trait from `HsmSigner`, added `SoftwareSigner` for testing without HSM hardware. Changed `Arc<HsmSigner>` to `Arc<dyn Signer>` across batch, gRPC, and server modules.
- [x] **Added retry logic with exponential backoff** - `RetryConfig` with configurable max retries, initial/max backoff, multiplier, and jitter. Applied to `timestamp()`, `get_public_key()`, and `health()`. See `sbt-client/src/client.rs`.
- [x] **Added server public key pinning** - `PinMode` enum supporting `None`, `TrustOnFirstUse`, and `Pinned(PublicKey)`. Validates notary public key on each timestamp response. See `sbt-client/src/client.rs`.
- [x] **Added test server infrastructure** - `TestServer` in `sbt-notary/src/testutil.rs` (behind `test-util` feature) runs an in-process notary with `SoftwareSigner` on a random port.
- [x] **Completed section 1.4 network tests** - 9 integration tests, 6 error case tests, 3 concurrent tests, and criterion benchmarks. All passing. See `sbt-client/tests/` and `sbt-client/benches/`.
- [x] **Completed section 2.2 TLS enhancements** - Certificate generation script (`scripts/generate-certs.sh`), TLS certificate pinning with SPKI SHA-256 verification (RFC 7469), TLS test infrastructure with `rcgen` runtime cert generation, 7 TLS integration tests, and `CERTIFICATES.md` documentation. See `sbt-client/src/tls.rs`, `sbt-client/tests/tls_integration.rs`.

---

## Critical Path to MVP

### 1. Network Protocol Implementation ✅ COMPLETED

**Status**: Completed
**Files created**:
- `proto/sbt.proto` - Protocol buffer definitions
- `sbt-notary/src/grpc.rs` - gRPC server implementation
- `sbt-client/src/grpc.rs` - gRPC client implementation
- `sbt-notary/build.rs` - Server proto build script
- `sbt-client/build.rs` - Client proto build script

#### 1.1 Protocol Buffer Schema ✅

- [x] Create `proto/sbt.proto` file
- [x] Define `StampRequest` message
- [x] Define `StampResponse` message
- [x] Define `SbtNotary` service with `Timestamp`, `GetPublicKey`, `Health` RPCs
- [x] Add build scripts to generate Rust code

#### 1.2 Server Implementation ✅

- [x] Implement gRPC server using `tonic`
- [x] Add `Timestamp` RPC handler
- [x] Add `GetPublicKey` RPC handler
- [x] Add `Health` check endpoint
- [x] Add request validation
- [x] Add error handling

#### 1.3 Client Implementation ✅

- [x] Implement gRPC client using `tonic`
- [x] Lazy connection management
- [x] Update CLI with `health` and `public-key` commands

#### 1.4 Remaining Network TODOs

- [x] Configure TLS/mTLS
- [x] Add retry logic with exponential backoff
- [x] Add server public key pinning
- [x] End-to-end integration tests
- [x] Test error cases (timeout, connection refused, etc.)
- [x] Test concurrent requests
- [x] Load testing (benchmark batch performance)

---

## Security Enhancements

### 2. TLS Implementation ✅ COMPLETED

**Status**: Completed
**Files created**:
- `sbt-notary/src/tls.rs` - Server TLS configuration
- `sbt-client/src/tls.rs` - Client TLS configuration

#### 2.1 Completed

- [x] Configure server TLS in notary (via `[tls]` config section)
- [x] Configure client TLS verification (via `--ca-cert` CLI option)
- [x] Add mTLS option for client authentication (via `--client-cert`, `--client-key`)
- [x] Update `notary.example.toml` with TLS configuration example

#### 2.2 Remaining TLS TODOs ✅

- [x] Add certificate generation script/documentation (`scripts/generate-certs.sh`)
- [x] Add TLS certificate pinning (`--tls-pin` CLI flag, SPKI SHA-256, RFC 7469)
- [x] Test TLS connections (7 TLS integration tests: TLS, mTLS, cert pin, no CA cert)
- [x] Document certificate management ([CERTIFICATES.md](CERTIFICATES.md))

**References**: See [SECURITY.md](SECURITY.md), [CERTIFICATES.md](CERTIFICATES.md)

### 3. Rate Limiting & DoS Protection ✅ COMPLETED

**Status**: Completed
**Files created**:
- `sbt-notary/src/rate_limit.rs` - Token bucket rate limiter implementation

#### 3.1 Server-Side Rate Limiting ✅

- [x] Per-client IP rate limiting (token bucket algorithm)
- [x] Global throughput limiting (global token bucket)
- [x] Configure limits in `notary.toml` via `[rate_limit]` section
- [x] Automatic cleanup of expired client entries
- [x] Background cleanup task for memory efficiency

#### 3.2 Request Validation ✅

- [x] Maximum request size enforcement
- [x] Request schema validation in gRPC layer
- [x] Reject malformed requests early

#### 3.3 Remaining Rate Limiting TODOs

- [ ] Add rate limit headers in responses (X-RateLimit-*)
- [ ] Log rate limit violations with client IP
- [ ] Add metrics for monitoring (rate limit hits, active clients)
- [ ] Optional: Proof-of-Work scheme for anti-spam

### 4. Authentication & Authorization ✅ COMPLETED

**Status**: Completed
**Files created**:
- `sbt-notary/src/auth.rs` - Authentication module with API key and mTLS support

#### 4.1 Implemented Features ✅

- [x] API key authentication via `x-api-key` header
- [x] mTLS client certificate authentication
- [x] Hybrid mode (API key OR mTLS)
- [x] Configurable anonymous access for health endpoints
- [x] API keys loadable from: config, file, or environment variable
- [x] Runtime API key management (add/remove/disable)
- [x] Client CLI support (`--api-key` or `SBT_API_KEY` env var)
- [x] Authentication documented in example config

#### 4.2 Remaining Auth TODOs

- [ ] OAuth 2.0 / JWT tokens support
- [ ] API key rotation mechanism
- [ ] Audit logging for authentication events
- [ ] Per-key rate limiting

---

## Security Enhancements

### 5. HSM Security Improvements 🔒 MEDIUM PRIORITY

**Status**: Partially implemented
**File**: `sbt-notary/src/hsm.rs`

#### 5.1 PIN Security

- [ ] Use `zeroize` crate to clear PIN from memory after use
- [ ] Ensure PINs are never logged
- [ ] Consider memory-locked storage for sensitive data

#### 5.2 Error Handling

- [ ] Sanitize HSM error messages in production (avoid information leakage)
- [ ] Improve `Drop` implementation to handle logout/finalize errors:
  ```rust
  impl Drop for HsmSigner {
      fn drop(&mut self) {
          if let Err(e) = self.session.logout() {
              tracing::error!("Failed to logout HSM session: {}", e);
          }
      }
  }
  ```

---

## Operational Features

### 6. Clock Synchronization 🕐 HIGH PRIORITY

**Status**: Not started
**Why**: Critical for timestamp accuracy and legal traceability

#### 6.1 PTP Integration (NRC Timelink)

**Goal**: Sub-microsecond accuracy with traceability to UTC(NRC)

- [ ] Configure PTP daemon (ptp4l/phc2sys) on notary server
- [ ] Document NRC Timelink Clock setup and network requirements
- [ ] Verify PTP-capable NIC with hardware timestamping support
- [ ] Configure PTP-aware network switches (or use boundary/transparent clocks)
- [ ] Test PTP sync stability and measure achieved accuracy
- [ ] Document traceability chain: NRC Cesium → Timelink → PTP → Notary

#### 6.2 Clock Monitoring

- [ ] Monitor PTP sync status (ptp4l servo state)
- [ ] Expose PTP offset in metrics (currentDS.offsetFromMaster)
- [ ] Alert on sync loss or excessive offset (>1μs threshold)
- [ ] Detect clock jumps and log anomalies
- [ ] Add clock health check endpoint (include PTP state)
- [ ] Log PTP sync status as part of audit trail

#### 6.3 Fallback & Resilience

- [ ] Configure NTP as fallback if PTP sync lost
- [ ] Define acceptable degradation policy (refuse to sign vs. warn)
- [ ] Document clock accuracy guarantees under different conditions

**Hardware Requirements**:
- PTP-capable NIC (Intel i210, i350, or similar with hardware timestamping)
- Network path with PTP-aware switches, or direct connection to Timelink

**References**:
- [NRC Timelink Service](https://nrc.canada.ca/en/certifications-evaluations-standards/time-frequency-services)
- [SECURITY.md - Clock Manipulation](SECURITY.md#6-clock-manipulation)

### 7. Monitoring & Observability 📊 MEDIUM PRIORITY

**Status**: Basic logging implemented

#### 7.1 Metrics (Prometheus)

- [ ] Add `prometheus` crate
- [ ] Metrics endpoint (`/metrics`)
- [ ] Counter: Total requests
- [ ] Counter: Successful timestamps
- [ ] Counter: Failed timestamps
- [ ] Histogram: Request latency
- [ ] Histogram: Batch size
- [ ] Histogram: HSM signing latency
- [ ] Gauge: Current batch queue size
- [ ] Gauge: Clock offset

#### 7.2 Health Checks

- [ ] `/health` endpoint (liveness)
- [ ] `/ready` endpoint (readiness)
- [ ] Check HSM connectivity
- [ ] Check clock sync status
- [ ] Return proper HTTP status codes

#### 7.3 Structured Logging

- [ ] Use `tracing` with JSON output option
- [ ] Log correlation IDs
- [ ] Log request metadata
- [ ] Configure log levels per module
- [ ] Add log sampling for high-volume events

#### 7.4 Distributed Tracing

- [ ] Add OpenTelemetry support
- [ ] Trace request flow
- [ ] Export to Jaeger/Zipkin

### 8. Deployment & Operations 🚀 MEDIUM PRIORITY

#### 8.1 Containerization

- [ ] Create `Dockerfile` for notary
- [ ] Create `Dockerfile` for client
- [ ] Multi-stage builds for small images
- [ ] Configure HSM in container
- [ ] Document volume mounts
- [ ] Add docker-compose example

#### 8.2 Service Management

- [ ] Create systemd service file
- [ ] Create launchd plist (macOS)
- [ ] Add service installation script
- [ ] Document service management

#### 8.3 Configuration Management

- [ ] Environment variable override support
- [ ] Config validation on startup
- [ ] Config reload without restart (SIGHUP)
- [ ] Document all config options

#### 8.4 Backup & Recovery

- [ ] HSM key backup procedures
- [ ] Config backup
- [ ] Document disaster recovery
- [ ] Test recovery procedures

---

## Advanced Features

### 9. Key Management 🔐 LOW PRIORITY

**Status**: Basic HSM support implemented

- [ ] Automated key generation script
- [ ] Key rotation mechanism
- [ ] Multiple active keys (overlap period)
- [ ] Old key retention for verification
- [ ] Key usage audit logging
- [ ] Document key lifecycle

### 10. Transparency & Auditability 📜 LOW PRIORITY

#### 10.1 Public Transparency Log

- [ ] Design log format
- [ ] Implement append-only log
- [ ] Add timestamp to log on creation
- [ ] Expose log via API
- [ ] Add log verification tools
- [ ] Document transparency guarantees

#### 10.2 Cross-Signing

- [ ] Support multiple notaries
- [ ] Cross-sign with other notaries
- [ ] Aggregate proofs from multiple sources
- [ ] Document federation protocol

### 11. Aggregation Layer 🌐 LOW PRIORITY

**Status**: Not started (future scaling)

**When needed**: When single notary can't handle load

- [ ] Design aggregator protocol
- [ ] Implement aggregator server
- [ ] Add timing uncertainty calculation
- [ ] Support multi-level aggregation
- [ ] Document aggregation topology
- [ ] Load testing with aggregators

**References**: See paper section "Scaling via Untrusted Aggregation Servers"

### 12. Additional Use Cases 🎯 LOW PRIORITY

#### 12.1 Random Beacon

- [ ] Expose nonces as random beacons
- [ ] Add `GetRandomness` API
- [ ] Prove unpredictability
- [ ] Document beacon usage
- [ ] Add beacon verification

#### 12.2 Clock Synchronization

- [ ] Implement delta-time measurement
- [ ] Support repeated measurements
- [ ] Calculate minimum latency
- [ ] Provide clock sync API
- [ ] Document sync protocol

**References**: See paper sections "Random Beacon" and "Clock Synchronization"

## Code Quality & Testing

### 13. Testing Improvements 🧪 MEDIUM PRIORITY

#### 13.1 Unit Tests

- [x] Core merkle tree tests
- [x] Primitives tests
- [x] Message tests
- [ ] Improve test coverage to >90%
- [ ] Add property-based tests (proptest) for:
  - Merkle path verification (for any tree, path must verify)
  - Timestamp arithmetic (no overflow, reversible operations)
  - Serialization round-trips
- [ ] Add fuzzing tests for input parsers

#### 13.2 Integration Tests

- [ ] End-to-end notary+client tests
- [ ] HSM integration tests (with real HSM)
- [ ] Network failure simulation
- [ ] Concurrent client tests
- [ ] Large batch tests (10k+ requests)

#### 13.3 Benchmarks

**Note**: `criterion` is in dependencies but no benchmarks implemented yet.

- [ ] Tree construction time vs batch size
- [ ] Signature verification benchmarks
- [ ] Path generation benchmarks
- [ ] Serialization benchmarks
- [ ] Batch processing throughput
- [ ] Add to CI/CD

#### 13.4 Security Testing

- [ ] Fuzzing input parsers
- [ ] Fuzzing Merkle path verification
- [ ] Timing side-channel analysis
- [ ] Memory safety audit
- [ ] Dependency audit automation (`cargo audit`)
- [ ] Penetration testing

### 14. Documentation 📖 ONGOING

- [x] README.md
- [x] ARCHITECTURE.md
- [x] PROTOCOL.md
- [x] SECURITY.md
- [x] DEVELOPMENT.md
- [x] QUICKSTART.md
- [ ] API documentation (rustdoc) - add to all public APIs
- [ ] Document Merkle tree duplicate-node behavior in protocol spec
- [ ] Deployment guide
- [ ] Operator manual
- [ ] Troubleshooting guide
- [ ] Performance tuning guide
- [ ] Create architecture diagrams (SVG)
- [ ] Record demo video

### 15. CI/CD Pipeline 🔄 MEDIUM PRIORITY

- [ ] GitHub Actions workflow
- [ ] Run tests on PR
- [ ] Run clippy on PR
- [ ] Run `cargo audit` on PR (check for known vulnerabilities)
- [ ] Build release binaries
- [ ] Publish to crates.io (when ready)
- [ ] Docker image publishing
- [ ] Version tagging automation
- [ ] Add "good first issue" labels for contributors
- [ ] Create CONTRIBUTING.md
- [ ] Set up issues/PR templates
- [ ] Add code of conduct

---

## Performance Optimization

### 16. Performance Tuning ⚡ LOW PRIORITY

**Do after baseline benchmarks**

#### 16.1 Tree Construction

- [ ] Benchmark current implementation
- [ ] Profile hot paths
- [ ] Optimize memory allocation
- [ ] Consider streaming path generation
- [ ] Parallel tree building (if beneficial)

#### 16.2 Batch Processing

- [ ] Tune batch parameters based on load
- [ ] Adaptive batching
- [ ] Pre-allocated buffers
- [ ] Zero-copy optimizations

#### 16.3 Network

- [ ] HTTP/2 multiplexing tuning
- [ ] Connection pooling
- [ ] Request pipelining
- [ ] Compression evaluation

---

#### 16.4 Memory Optimization

- [ ] Document memory requirements for large batches (~64 bytes × 2N for N leaves)
- [ ] Consider streaming Merkle path generation for very large batches (>100k leaves)
- [ ] Pre-allocated buffers for batch processing

---

## Future Research & Enhancements

### 17. Post-Quantum Cryptography 🔮 RESEARCH

**Timeline**: When PQ standards mature

- [ ] Research PQ signature schemes
- [ ] Hybrid signatures (Ed25519 + PQ)
- [ ] Benchmark PQ performance
- [ ] Migration path from Ed25519
- [ ] Document PQ support

### 18. Advanced Security Features 🛡️ RESEARCH

- [ ] Threshold signatures (multiple HSMs)
- [ ] Multiparty computation for signing
- [ ] Secure enclaves (SGX, TrustZone)
- [ ] TPM integration
- [ ] Hardware attestation

### 19. Scalability Research 📈 RESEARCH

- [ ] Sharding strategies
- [ ] Geographic distribution
- [ ] CDN for proof delivery
- [ ] Multicast beacon delivery
- [ ] Bloom filters for proof existence

---

## Release Checklist

### 20. Storage Evaluation 💾 LOW PRIORITY

**Current**: Using `sled` for client storage

- [ ] Evaluate `redb` as alternative (more actively maintained)
- [ ] Consider SQLite with `rusqlite` for better tooling
- [ ] Document storage requirements and recommendations

---

## Release Checklist

### Version 0.1.0 (MVP)

- [x] Fix critical verification bug
- [x] Add domain separation to signatures
- [x] Network protocol implemented
- [x] TLS configured
- [x] Basic rate limiting
- [x] Basic authentication (API keys minimum)
- [ ] Documentation complete
- [ ] Integration tests passing
- [ ] Security audit completed
- [ ] Example deployment tested
- [ ] Tag v0.1.0

### Version 0.2.0 (Production)

- [ ] Clock synchronization
- [ ] Monitoring/metrics
- [ ] Authentication
- [ ] Transparency log
- [ ] Load tested
- [ ] Production deployment guide
- [ ] Tag v0.2.0

### Version 1.0.0 (Stable)

- [ ] All critical features
- [ ] Stable API
- [ ] Full documentation
- [ ] Security audited
- [ ] Multiple production deployments
- [ ] Performance benchmarks
- [ ] Tag v1.0.0

---

## Priority Legend

- 🔴 **HIGH PRIORITY**: Blocking MVP or security-critical
- 🟡 **MEDIUM PRIORITY**: Important for production readiness
- 🟢 **LOW PRIORITY**: Nice to have, future enhancement
- 🔵 **RESEARCH**: Exploratory, no immediate timeline

---

## How to Contribute

1. Pick a TODO item
2. Create feature branch: `git checkout -b feature/item-name`
3. Implement with tests
4. Update relevant documentation
5. Submit PR with reference to TODO item
6. Check off item when merged

---

## Notes

- Items marked with ⚠️ are blocking production deployment
- See [SECURITY.md](SECURITY.md) for security-related TODOs
- See [DEVELOPMENT.md](DEVELOPMENT.md) for development setup
- Update this file as priorities change

**Last Updated**: 2026-02-18

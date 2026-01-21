# Stamp/Beacon Trees TODO List

## Recently Completed ✅

- [x] **Fixed critical Merkle path verification bug** - The comparison was checking `computed_root != computed_root` (always false). Fixed in `sbt-core/src/verify.rs`.
- [x] **Added domain separation to signatures** - Added `SBT-v1:` prefix to prevent cross-protocol signature reuse attacks. See `sbt-types/src/messages.rs`.
- [x] **Made `Digest` type `Copy`** - Optimized by adding `Copy` derive and removing unnecessary `.clone()` calls.
- [x] **Improved unsafe unwrap() handling** - Replaced bare `unwrap()` with `while let` pattern and `expect()` with messages in `sbt-core/src/merkle.rs`.
- [x] **Added thread safety documentation** - Documented `NonceGenerator` thread safety requirements in `sbt-core/src/nonce.rs`.

---

## Critical Path to MVP

### 1. Network Protocol Implementation ⚠️ HIGH PRIORITY

**Status**: Not started
**Estimated Effort**: 1-2 days
**Blocking**: Production deployment

#### 1.1 Define Protocol Buffer Schema

- [ ] Create `proto/Stamp/Beacon Trees.proto` file
- [ ] Define `StampRequest` message
- [ ] Define `StampResponse` message
- [ ] Define `Stamp/Beacon TreesNotary` service
- [ ] Add `GetPublicKey` RPC method
- [ ] Add build script to generate Rust code

**Files to create**:
```
proto/
  └── Stamp/Beacon Trees.proto
```

#### 1.2 Implement Server (Notary)

**File**: [notary/src/server.rs](notary/src/server.rs#L53)

- [ ] Implement gRPC server using `tonic`
- [ ] Add `Timestamp` RPC handler
- [ ] Add `GetPublicKey` RPC handler
- [ ] Configure TLS/mTLS
- [ ] Add request validation
- [ ] Add error handling
- [ ] Add request logging
- [ ] Add health check endpoint
- [ ] Write integration tests

**Key Location**: See TODO comment at line 53

#### 1.3 Implement Client

**File**: [client/src/client.rs](client/src/client.rs#L48)

- [ ] Implement gRPC client using `tonic`
- [ ] Implement `send_request()` method
- [ ] Add retry logic with exponential backoff
- [ ] Add timeout handling
- [ ] Add TLS configuration
- [ ] Add server public key pinning
- [ ] Write integration tests
- [ ] Update CLI to use network client

**Key Location**: See TODO comment at line 48

#### 1.4 Testing

- [ ] End-to-end test: client → server → response
- [ ] Test error cases (timeout, connection refused, etc.)
- [ ] Test concurrent requests
- [ ] Load testing (benchmark batch performance)
- [ ] Network failure scenarios

---

## Security Enhancements

### 2. TLS Implementation 🔒 HIGH PRIORITY

**Status**: Not started
**Blocks**: Production deployment

- [ ] Generate TLS certificates for notary
- [ ] Configure server TLS in notary
- [ ] Configure client TLS verification
- [ ] Add certificate pinning option
- [ ] Document certificate management
- [ ] Add mTLS option for client authentication
- [ ] Test certificate rotation

**References**: See [SECURITY.md](SECURITY.md)

### 3. Rate Limiting & DoS Protection 🛡️ HIGH PRIORITY

**Status**: Not started
**Blocking**: Production deployment

#### 3.1 Server-Side Rate Limiting

- [ ] Per-client IP rate limiting
- [ ] Global throughput limiting
- [ ] Configure limits in `notary.toml`
- [ ] Add rate limit headers in responses
- [ ] Log rate limit violations
- [ ] Add metrics for monitoring

#### 3.2 Request Validation

- [ ] Maximum request size
- [ ] Batch size enforcement
- [ ] Request schema validation
- [ ] Reject malformed requests early

#### 3.3 Optional: Proof-of-Work

- [ ] Design PoW scheme
- [ ] Implement client solver
- [ ] Implement server verifier
- [ ] Make configurable (disabled by default)

### 4. Authentication & Authorization 🔑 HIGH PRIORITY

**Status**: Not started
**Blocking**: Production deployment

**Options to consider**:
- [ ] API key authentication (minimum viable)
- [ ] OAuth 2.0 / JWT tokens
- [ ] Mutual TLS (mTLS) - recommended for production
- [ ] Anonymous public access (with rate limits)

**Implementation**:
- [ ] Choose authentication method
- [ ] Add auth middleware to server
- [ ] Update client to provide credentials
- [ ] Document authentication setup
- [ ] Add auth to example configs

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
**Why**: Critical for timestamp accuracy

#### 5.1 Roughtime Integration

- [ ] Research Roughtime protocol
- [ ] Add Roughtime client to notary
- [ ] Query multiple time sources
- [ ] Detect outliers
- [ ] Expose clock offset in metrics
- [ ] Alert on clock drift
- [ ] Document time source configuration

#### 5.2 Clock Monitoring

- [ ] Monitor system clock vs Roughtime
- [ ] Detect clock jumps
- [ ] Log clock anomalies
- [ ] Add clock health check endpoint

**References**: See [SECURITY.md - Clock Manipulation](SECURITY.md#6-clock-manipulation)

### 7. Monitoring & Observability 📊 MEDIUM PRIORITY

**Status**: Basic logging implemented

#### 6.1 Metrics (Prometheus)

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

#### 6.2 Health Checks

- [ ] `/health` endpoint (liveness)
- [ ] `/ready` endpoint (readiness)
- [ ] Check HSM connectivity
- [ ] Check clock sync status
- [ ] Return proper HTTP status codes

#### 6.3 Structured Logging

- [ ] Use `tracing` with JSON output option
- [ ] Log correlation IDs
- [ ] Log request metadata
- [ ] Configure log levels per module
- [ ] Add log sampling for high-volume events

#### 6.4 Distributed Tracing

- [ ] Add OpenTelemetry support
- [ ] Trace request flow
- [ ] Export to Jaeger/Zipkin

### 8. Deployment & Operations 🚀 MEDIUM PRIORITY

#### 7.1 Containerization

- [ ] Create `Dockerfile` for notary
- [ ] Create `Dockerfile` for client
- [ ] Multi-stage builds for small images
- [ ] Configure HSM in container
- [ ] Document volume mounts
- [ ] Add docker-compose example

#### 7.2 Service Management

- [ ] Create systemd service file
- [ ] Create launchd plist (macOS)
- [ ] Add service installation script
- [ ] Document service management

#### 7.3 Configuration Management

- [ ] Environment variable override support
- [ ] Config validation on startup
- [ ] Config reload without restart (SIGHUP)
- [ ] Document all config options

#### 7.4 Backup & Recovery

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

#### 9.1 Public Transparency Log

- [ ] Design log format
- [ ] Implement append-only log
- [ ] Add timestamp to log on creation
- [ ] Expose log via API
- [ ] Add log verification tools
- [ ] Document transparency guarantees

#### 9.2 Cross-Signing

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

#### 11.1 Random Beacon

- [ ] Expose nonces as random beacons
- [ ] Add `GetRandomness` API
- [ ] Prove unpredictability
- [ ] Document beacon usage
- [ ] Add beacon verification

#### 11.2 Clock Synchronization

- [ ] Implement delta-time measurement
- [ ] Support repeated measurements
- [ ] Calculate minimum latency
- [ ] Provide clock sync API
- [ ] Document sync protocol

**References**: See paper sections "Random Beacon" and "Clock Synchronization"

### 13. Protocol Compatibility 🔗 LOW PRIORITY

#### 12.1 OpenTimestamps Compatibility

- [ ] Research OTS format
- [ ] Add OTS export option
- [ ] Add OTS import option
- [ ] Bridge to OTS calendar servers
- [ ] Document compatibility

#### 12.2 RFC 3161 Support

- [ ] Implement RFC 3161 TSA protocol
- [ ] Convert proofs to RFC 3161 format
- [ ] Document compatibility

---

## Code Quality & Testing

### 14. Testing Improvements 🧪 MEDIUM PRIORITY

#### 14.1 Unit Tests

- [x] Core merkle tree tests
- [x] Primitives tests
- [x] Message tests
- [ ] Improve test coverage to >90%
- [ ] Add property-based tests (proptest) for:
  - Merkle path verification (for any tree, path must verify)
  - Timestamp arithmetic (no overflow, reversible operations)
  - Serialization round-trips
- [ ] Add fuzzing tests for input parsers

#### 14.2 Integration Tests

- [ ] End-to-end notary+client tests
- [ ] HSM integration tests (with real HSM)
- [ ] Network failure simulation
- [ ] Concurrent client tests
- [ ] Large batch tests (10k+ requests)

#### 14.3 Benchmarks

**Note**: `criterion` is in dependencies but no benchmarks implemented yet.

- [ ] Tree construction time vs batch size
- [ ] Signature verification benchmarks
- [ ] Path generation benchmarks
- [ ] Serialization benchmarks
- [ ] Batch processing throughput
- [ ] Add to CI/CD

#### 14.4 Security Testing

- [ ] Fuzzing input parsers
- [ ] Fuzzing Merkle path verification
- [ ] Timing side-channel analysis
- [ ] Memory safety audit
- [ ] Dependency audit automation (`cargo audit`)
- [ ] Penetration testing

### 15. Documentation 📖 ONGOING

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

### 16. CI/CD Pipeline 🔄 MEDIUM PRIORITY

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

### 17. Performance Tuning ⚡ LOW PRIORITY

**Do after baseline benchmarks**

#### 17.1 Tree Construction

- [ ] Benchmark current implementation
- [ ] Profile hot paths
- [ ] Optimize memory allocation
- [ ] Consider streaming path generation
- [ ] Parallel tree building (if beneficial)

#### 17.2 Batch Processing

- [ ] Tune batch parameters based on load
- [ ] Adaptive batching
- [ ] Pre-allocated buffers
- [ ] Zero-copy optimizations

#### 17.3 Network

- [ ] HTTP/2 multiplexing tuning
- [ ] Connection pooling
- [ ] Request pipelining
- [ ] Compression evaluation

---

#### 17.4 Memory Optimization

- [ ] Document memory requirements for large batches (~64 bytes × 2N for N leaves)
- [ ] Consider streaming Merkle path generation for very large batches (>100k leaves)
- [ ] Pre-allocated buffers for batch processing

---

## Future Research & Enhancements

### 18. Post-Quantum Cryptography 🔮 RESEARCH

**Timeline**: When PQ standards mature

- [ ] Research PQ signature schemes
- [ ] Hybrid signatures (Ed25519 + PQ)
- [ ] Benchmark PQ performance
- [ ] Migration path from Ed25519
- [ ] Document PQ support

### 19. Advanced Security Features 🛡️ RESEARCH

- [ ] Threshold signatures (multiple HSMs)
- [ ] Multiparty computation for signing
- [ ] Secure enclaves (SGX, TrustZone)
- [ ] TPM integration
- [ ] Hardware attestation

### 20. Scalability Research 📈 RESEARCH

- [ ] Sharding strategies
- [ ] Geographic distribution
- [ ] CDN for proof delivery
- [ ] Multicast beacon delivery
- [ ] Bloom filters for proof existence

---

## Release Checklist

### 21. Storage Evaluation 💾 LOW PRIORITY

**Current**: Using `sled` for client storage

- [ ] Evaluate `redb` as alternative (more actively maintained)
- [ ] Consider SQLite with `rusqlite` for better tooling
- [ ] Document storage requirements and recommendations

---

## Release Checklist

### Version 0.1.0 (MVP)

- [x] Fix critical verification bug
- [x] Add domain separation to signatures
- [ ] Network protocol implemented
- [ ] TLS configured
- [ ] Basic authentication (API keys minimum)
- [ ] Basic rate limiting
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

**Last Updated**: 2026-01-21

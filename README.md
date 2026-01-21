# SBT (Stamp/Beacon Trees)

A Rust implementation of Stamp/Beacon Trees for secure, precise, trusted timestamping.

## Overview

SBT is a cryptographic timestamping system based on the Stamp/Beacon Tree construction. It provides:

- **Trusted Timestamping**: Cryptographic proof that data existed at a specific time
- **High Precision**: Nanosecond-level timing precision with per-leaf delta times
- **Verifiable**: Independent verification of timestamp proofs using Merkle paths
- **Scalable**: Batch processing with efficient tree construction
- **HSM-Backed**: Signing keys secured in Hardware Security Modules

## Architecture

The project is organized as a Cargo workspace with four main crates:

### 1. `sbt-types`
Core protocol definitions and data structures:
- Cryptographic primitives (Digest, Signature, PublicKey, Nonce)
- Protocol messages (StampRequest, StampResponse)
- Timestamp proofs and Merkle paths
- Zero I/O dependencies

### 2. `sbt-core`
Cryptographic and tree construction logic:
- Merkle tree builder with per-leaf timing deltas
- Proof verification
- Nonce generation
- Pure crypto operations, no network/storage dependencies

### 3. `sbt-notary`
The trusted timestamping server:
- Receives client timestamp requests via gRPC
- Builds stamp/beacon trees with precise timing
- Signs trees using HSM-backed keys (PKCS#11)
- Batch processing for scalability
- TLS/mTLS support for secure connections
- Rate limiting for DoS protection
- API key and certificate-based authentication

### 4. `sbt-client`
Client library and CLI tool:
- Submit files/data for timestamping via gRPC
- Verify timestamp proofs
- Store and manage proofs locally
- Export/import proofs as JSON
- TLS/mTLS support for secure connections
- API key authentication support
- Command-line interface for all operations

## Getting Started

### Prerequisites

- Rust 1.70+ (2021 edition)
- HSM with PKCS#11 support (for notary server)
  - Development: SoftHSM works for testing
  - Production: YubiHSM, AWS CloudHSM, etc.

### Building

```bash
# Build all crates
cargo build --release

# Build specific crate
cargo build -p sbt-notary --release
cargo build -p sbt-client --release
```

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test -p sbt-core
```

## Usage

### Notary Server

1. **Configure HSM**:
   - Set up your HSM and generate an Ed25519 signing key
   - Note the key label and slot ID

2. **Create configuration**:

```bash
# Generate default config
sbt-notary

# This creates notary.toml - edit it with your HSM settings
```

Example `notary.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080
max_connections = 1000

[hsm]
pkcs11_library = "/usr/lib/softhsm/libsofthsm2.so"
slot_id = 0
key_label = "sbt-notary-key"

[batch]
max_batch_size = 1000
max_wait_ms = 100
batch_interval_ms = 1000

# Optional: TLS configuration
[tls]
cert_path = "/etc/sbt/server.crt"
key_path = "/etc/sbt/server.key"
# ca_cert_path = "/etc/sbt/ca.crt"  # Enable mTLS

# Optional: Rate limiting
[rate_limit]
enabled = true
per_ip_rps = 100
per_ip_burst = 200
global_rps = 10000
global_burst = 20000

# Optional: Authentication
[auth]
enabled = true
mode = "api_key"  # or "mtls_only" or "hybrid"
allow_anonymous_health = true
# API keys can be loaded from environment: SBT_API_KEYS="key1:secret1,key2:secret2"
```

See `notary.example.toml` for full configuration options.

3. **Set HSM PIN**:

```bash
export SBT_HSM_PIN="your-hsm-pin"
```

4. **Run server**:

```bash
sbt-notary notary.toml
```

### Client

**Basic usage**:

```bash
# Timestamp a file
sbt timestamp document.pdf

# Verify a timestamp (by digest or file)
sbt verify abc123...
sbt verify document.pdf

# List stored proofs
sbt list

# Show proof details
sbt show abc123...

# Export/Import proofs
sbt export abc123... -o proof.json
sbt import proof.json

# Check server health
sbt health

# Get notary's public key
sbt public-key
```

**Connection options**:

```bash
# Connect to a specific server
sbt -s http://notary.example.com:8080 timestamp document.pdf

# With TLS (uses system CA roots)
sbt -s https://notary.example.com:8080 timestamp document.pdf

# With custom CA certificate
sbt -s https://notary.example.com:8080 --ca-cert ca.crt timestamp document.pdf

# With mTLS client certificate
sbt -s https://notary.example.com:8080 \
    --ca-cert ca.crt \
    --client-cert client.crt \
    --client-key client.key \
    timestamp document.pdf

# With API key authentication
sbt --api-key "your-secret-key" timestamp document.pdf

# Or via environment variable
export SBT_API_KEY="your-secret-key"
sbt timestamp document.pdf
```

## How It Works

### Stamp/Beacon Tree Construction

1. **Client submits digest**: Client sends hash of their data to notary
2. **Batching**: Notary accumulates requests over a time interval
3. **Tree building**:
   - Each request gets a unique random nonce
   - Leaf hash = H(digest || nonce)
   - Per-leaf timing delta calculated relative to root timestamp
   - Binary Merkle tree constructed from leaves
4. **Signing**: Notary signs (root_hash || timestamp) using HSM key
5. **Response**: Each client receives:
   - Their nonce
   - Merkle path to root
   - Delta time for their leaf
   - Root timestamp and signature
   - Notary's public key

### Verification

To verify a timestamp proof:

1. Compute leaf hash: H(digest || nonce)
2. Follow Merkle path to compute root hash
3. Verify signature on (root_hash || root_timestamp)
4. Leaf timestamp = root_timestamp + delta_nanos

All verification can be done offline with just the proof and notary's public key.

## Security Model

### Trusted Components

- **Notary Server**: Must maintain accurate time and protect signing keys
- **HSM**: Protects signing keys from extraction
- **System Clock**: Notary relies on system clock accuracy

### Threat Model

- Clients are untrusted
- Network is untrusted (use TLS in production)
- Notary server code is auditable
- HSM prevents key extraction even if server is compromised
- Per-leaf nonces prevent sibling attacks
- Merkle tree structure ensures proof integrity
- Domain-separated signatures prevent cross-protocol attacks

### Security Features

- **TLS/mTLS**: Encrypted connections with optional client certificate verification
- **API Key Authentication**: Header-based authentication for client identification
- **Rate Limiting**: Token bucket algorithm protects against DoS attacks
- **Request Size Limits**: Prevents resource exhaustion from oversized requests

### Current Limitations

1. **No clock sync**: Clients must trust notary's clock
2. **Single notary**: No federation support yet
3. **No aggregation**: Untrusted aggregators not implemented

## Future Work

- [x] ~~Implement network protocol (gRPC)~~
- [x] ~~TLS/mTLS support~~
- [x] ~~Rate limiting~~
- [x] ~~API key authentication~~
- [ ] Clock synchronization (Roughtime-style)
- [ ] Untrusted aggregation servers
- [ ] Random beacon functionality
- [ ] Notary federation support
- [ ] OpenTimestamps compatibility
- [ ] Public transparency log
- [ ] OAuth 2.0 / JWT token support

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please ensure:
- All tests pass: `cargo test --workspace`
- Code is formatted: `cargo fmt --all`
- No clippy warnings: `cargo clippy --workspace`

## References

- [Stamp/Beacon Trees Paper](https://petertodd.org/2023/stamp-beacon-trees) (concept document)
- [OpenTimestamps](https://opentimestamps.org/)
- [Roughtime](https://roughtime.googlesource.com/roughtime)

# Stamp/Beacon Trees

A Rust implementation of Stamp/Beacon Trees for secure, precise, trusted timestamping.

## Overview

Stamp/Beacon Trees is a cryptographic timestamping system based on the Stamp/Beacon Tree construction. It provides:

- **Trusted Timestamping**: Cryptographic proof that data existed at a specific time
- **High Precision**: Nanosecond-level timing precision with per-leaf delta times
- **Verifiable**: Independent verification of timestamp proofs using Merkle paths
- **Scalable**: Batch processing with efficient tree construction
- **HSM-Backed**: Signing keys secured in Hardware Security Modules

## Architecture

The project is organized as a Cargo workspace with four main crates:

### 1. `Stamp/Beacon Trees-types`
Core protocol definitions and data structures:
- Cryptographic primitives (Digest, Signature, PublicKey, Nonce)
- Protocol messages (StampRequest, StampResponse)
- Timestamp proofs and Merkle paths
- Zero I/O dependencies

### 2. `Stamp/Beacon Trees-core`
Cryptographic and tree construction logic:
- Merkle tree builder with per-leaf timing deltas
- Proof verification
- Nonce generation
- Pure crypto operations, no network/storage dependencies

### 3. `Stamp/Beacon Trees-notary`
The trusted timestamping server:
- Receives client timestamp requests
- Builds stamp/beacon trees with precise timing
- Signs trees using HSM-backed keys (PKCS#11)
- Batch processing for scalability
- Current state storage (no historical archive)

### 4. `Stamp/Beacon Trees-client`
Client library and CLI tool:
- Submit files/data for timestamping
- Verify timestamp proofs
- Store and manage proofs locally
- Export/import proofs as JSON
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
cargo build -p Stamp/Beacon Trees-notary --release
cargo build -p Stamp/Beacon Trees-client --release
```

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test -p Stamp/Beacon Trees-core
```

## Usage

### Notary Server

1. **Configure HSM**:
   - Set up your HSM and generate an Ed25519 signing key
   - Note the key label and slot ID

2. **Create configuration**:

```bash
# Generate default config
Stamp/Beacon Trees-notary

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
key_label = "Stamp/Beacon Trees-notary-key"

[batch]
max_batch_size = 1000
max_wait_ms = 100
batch_interval_ms = 1000
```

3. **Set HSM PIN**:

```bash
export Stamp/Beacon Trees_HSM_PIN="your-hsm-pin"
```

4. **Run server**:

```bash
Stamp/Beacon Trees-notary notary.toml
```

### Client

**Timestamp a file**:

```bash
Stamp/Beacon Trees timestamp document.pdf
```

**Verify a timestamp**:

```bash
# By digest
Stamp/Beacon Trees verify abc123...

# By file
Stamp/Beacon Trees verify document.pdf
```

**List stored proofs**:

```bash
Stamp/Beacon Trees list
```

**Show proof details**:

```bash
Stamp/Beacon Trees show abc123...
```

**Export/Import proofs**:

```bash
# Export to JSON
Stamp/Beacon Trees export abc123... -o proof.json

# Import from JSON
Stamp/Beacon Trees import proof.json
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
- Network is untrusted (MITM possible)
- Notary server code is auditable
- HSM prevents key extraction even if server is compromised
- Per-leaf nonces prevent sibling attacks
- Merkle tree structure ensures proof integrity

### Current Limitations

1. **No clock sync**: Clients must trust notary's clock
2. **Single notary**: No federation support yet
3. **No aggregation**: Untrusted aggregators not implemented
4. **Network protocol**: gRPC/HTTP implementation pending

## Future Work

- [ ] Implement network protocol (gRPC)
- [ ] Clock synchronization (Roughtime-style)
- [ ] Untrusted aggregation servers
- [ ] Random beacon functionality
- [ ] Notary federation support
- [ ] OpenTimestamps compatibility
- [ ] Public transparency log

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

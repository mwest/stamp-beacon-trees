# SBT Quick Start Guide

Get up and running with SBT (Stamp/Beacon Trees) timestamping in 5 minutes.

## Prerequisites

- Rust 1.70+ installed
- For notary: SoftHSM2 (development) or hardware HSM (production)

## Installation

```bash
# Clone repository
git clone https://github.com/mwest/stamp-beacon-trees.git
cd stamp-beacon-trees

# Build all crates
cargo build --release

# Binaries will be in target/release/
ls target/release/sbt*
```

## Setup: Development Notary

### 1. Install SoftHSM

**Ubuntu/Debian**:
```bash
sudo apt-get install softhsm2
```

**macOS**:
```bash
brew install softhsm
```

**Windows**: Download from [OpenSC project](https://github.com/OpenSC/OpenSC/wiki)

### 2. Initialize SoftHSM Token

```bash
# Create token
softhsm2-util --init-token \
  --slot 0 \
  --label "sbt-dev" \
  --pin 1234 \
  --so-pin 5678

# Verify token created
softhsm2-util --show-slots
```

### 3. Generate Ed25519 Key

**Note**: SoftHSM 2.6.0+ required for Ed25519 support.

If your SoftHSM doesn't support Ed25519, you can use RSA for testing (not recommended for production):

```bash
# Using pkcs11-tool (if Ed25519 supported)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type EC:edwards25519 \
  --label "sbt-notary-key"

# OR for testing with RSA (if Ed25519 not available)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type RSA:2048 \
  --label "sbt-notary-key"
```

### 4. Configure Notary

```bash
# Create config from example
cp notary.example.toml notary.toml

# Edit notary.toml:
# - Verify pkcs11_library path
# - Set key_label = "sbt-notary-key"
# - Set slot_id = 0
```

Example `notary.toml`:
```toml
[server]
host = "127.0.0.1"
port = 8080
max_connections = 100

[hsm]
pkcs11_library = "/usr/lib/softhsm/libsofthsm2.so"
slot_id = 0
key_label = "sbt-notary-key"

[batch]
max_batch_size = 100
max_wait_ms = 100
batch_interval_ms = 1000
```

### 5. Set HSM PIN

```bash
export SBT_HSM_PIN="1234"
```

### 6. Run Notary Server

```bash
cargo run --release -p sbt-notary

# Should see:
# INFO sbt_notary: Initializing notary server
# INFO sbt_notary: HSM signer initialized, public key: abc123...
# INFO sbt_notary: Notary server running on 127.0.0.1:8080
```

**Note**: Currently the server doesn't accept network requests (network layer TODO). You can test using the library API directly.

## Usage: Client (Library Example)

Since the network layer isn't implemented yet, here's how to use the core libraries:

### Create a Timestamp (Library Usage)

Create `examples/my_timestamp.rs`:

```rust
use sbt_core::{LeafData, NonceGenerator, StampTreeBuilder};
use sbt_types::{Digest, Timestamp};

fn main() {
    // 1. Hash your data
    let data = b"Important document content";
    let hash = blake3::hash(data);
    let digest = Digest::new(*hash.as_bytes());

    println!("Data digest: {}", digest);

    // 2. In a real system, this happens on the notary
    let mut nonce_gen = NonceGenerator::new();
    let nonce = nonce_gen.generate();

    // 3. Build a simple single-leaf tree
    let mut builder = StampTreeBuilder::new();
    builder.add_leaf(LeafData {
        digest: digest.clone(),
        nonce: nonce.clone(),
        delta_nanos: 0,
    });

    let timestamp = Timestamp::now();
    let tree = builder.build(timestamp);

    println!("Tree root: {}", tree.root_hash());
    println!("Timestamp: {}", tree.root_timestamp());

    // 4. Generate Merkle path
    let path = tree.generate_path(0).unwrap();
    println!("Merkle path length: {}", path.siblings.len());
}
```

Run it:
```bash
cargo run --example my_timestamp
```

### Verify a Proof

```rust
use sbt_core::verify_proof;
use sbt_types::TimestampProof;

fn verify_example(proof: TimestampProof) {
    match verify_proof(&proof) {
        Ok(()) => {
            println!("✓ Proof verified!");
            println!("  Timestamp: {}", proof.leaf_timestamp());
            println!("  Notary: {}", proof.notary_pubkey);
        }
        Err(e) => {
            println!("✗ Verification failed: {}", e);
        }
    }
}
```

## Testing

### Run All Tests

```bash
# All tests except HSM integration tests
cargo test --workspace

# Include HSM tests (requires configured HSM)
cargo test --workspace -- --ignored
```

### Run Example

```bash
# Basic usage example
cargo run --example basic_usage
```

Expected output:
```
SBT (Stamp/Beacon Trees) Example
=================================

Data to timestamp:
  1. "Hello, world!"
  2. "Timestamp this document"
  3. "Another piece of data"

Digests:
  1. abc123...
  2. def456...
  3. ghi789...

Stamp Tree Built:
  Leaves:         3
  Root Hash:      xyz...
  Root Timestamp: 2024-01-15 10:30:45.123456789 UTC

Merkle Paths:
  Leaf 1 (index 0):
    Digest:      abc123...
    Delta:       -100000000 ns
    Leaf Time:   2024-01-15 10:30:45.023456789 UTC
    Path Length: 2
    ✓ Path verified
  ...

✓ Example completed successfully!
```

## Next Steps

### For Development

1. **Explore the code**:
   - Start with [sbt-types/src/messages.rs](sbt-types/src/messages.rs) for protocol
   - Look at [sbt-core/src/merkle.rs](sbt-core/src/merkle.rs) for tree construction
   - Check [sbt-notary/src/batch.rs](sbt-notary/src/batch.rs) for batching logic

2. **Read documentation**:
   - [ARCHITECTURE.md](ARCHITECTURE.md) - System design
   - [PROTOCOL.md](PROTOCOL.md) - Protocol specification
   - [DEVELOPMENT.md](DEVELOPMENT.md) - Developer guide

3. **Implement networking**:
   - Add gRPC server to [sbt-notary/src/server.rs](sbt-notary/src/server.rs)
   - Add gRPC client to [sbt-client/src/client.rs](sbt-client/src/client.rs)
   - See TODO comments in code

### For Production

1. **Security hardening**:
   - Read [SECURITY.md](SECURITY.md)
   - Use hardware HSM (not SoftHSM)
   - Implement TLS
   - Add rate limiting

2. **Operational setup**:
   - Configure NTP for accurate time
   - Set up monitoring
   - Create backup procedures
   - Test disaster recovery

3. **Deployment**:
   - Use systemd service
   - Configure firewall
   - Set up log rotation
   - Enable audit logging

## Troubleshooting

### "cargo: command not found"

Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### "PKCS#11 initialization failed"

Check SoftHSM installation:
```bash
# Find library location
find /usr -name "libsofthsm2.so"

# Update notary.toml with correct path
```

### "Key not found"

Verify key was created:
```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --list-objects
```

### "HSM PIN not configured"

Set environment variable:
```bash
export SBT_HSM_PIN="your-pin"
```

Or add to shell profile:
```bash
echo 'export SBT_HSM_PIN="1234"' >> ~/.bashrc
source ~/.bashrc
```

### Build Errors

Update dependencies:
```bash
cargo update
cargo clean
cargo build
```

## Quick Reference

### Commands

```bash
# Build
make build              # or: cargo build

# Test
make test              # or: cargo test --workspace

# Run notary
make run-notary        # or: cargo run -p sbt-notary

# Run example
make example           # or: cargo run --example basic_usage

# Format code
make fmt               # or: cargo fmt --all

# Lint
make lint              # or: cargo clippy --workspace
```

### File Locations

- Notary config: `notary.toml`
- Client storage: `.sbt/` (default)
- Logs: stdout (configure with RUST_LOG)
- HSM: `/usr/lib/softhsm/libsofthsm2.so` (typical)

### Environment Variables

- `SBT_HSM_PIN`: HSM PIN (required)
- `RUST_LOG`: Log level (debug, info, warn, error)

## Getting Help

- Read [README.md](README.md) for overview
- Check [DEVELOPMENT.md](DEVELOPMENT.md) for details
- File issues on GitHub
- Ask questions in discussions

## What's Next?

The current implementation has everything except network communication:

1. **Core crypto**: ✅ Done
2. **Tree construction**: ✅ Done
3. **HSM integration**: ✅ Done
4. **Batch processing**: ✅ Done
5. **Client library**: ✅ Done
6. **CLI tool**: ✅ Done
7. **Network protocol**: ⚠️ TODO

To make it production-ready, implement the network layer following the placeholders in:
- [sbt-notary/src/server.rs](sbt-notary/src/server.rs)
- [sbt-client/src/client.rs](sbt-client/src/client.rs)

Happy timestamping! 🕐

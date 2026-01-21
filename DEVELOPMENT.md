# Development Guide

## Project Structure

```
sbt/
├── sbt-types/      # Protocol definitions (zero dependencies)
│   ├── primitives  # Digest, Signature, Nonce, Timestamp
│   ├── messages    # StampRequest, StampResponse, TimestampProof
│   └── error       # Error types
│
├── sbt-core/       # Cryptographic logic
│   ├── merkle      # Tree construction and path generation
│   ├── nonce       # Nonce generation
│   └── verify      # Proof verification
│
├── sbt-notary/     # Trusted server
│   ├── config      # Configuration management
│   ├── hsm         # PKCS#11 HSM integration
│   ├── batch       # Request batching and tree building
│   └── server      # Network server (TODO)
│
└── sbt-client/     # Client library + CLI
    ├── client      # Network client (TODO)
    ├── storage     # Local proof storage
    └── main        # CLI interface
```

## Development Setup

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
```

### 2. Install Development Tools

```bash
# Formatter and linter
rustup component add rustfmt clippy

# PKCS#11 tools (for HSM testing)
# Ubuntu/Debian:
sudo apt-get install softhsm2 opensc

# macOS:
brew install softhsm opensc
```

### 3. Set Up SoftHSM (for testing)

```bash
# Initialize SoftHSM token
softhsm2-util --init-token --slot 0 --label "sbt-test" --pin 1234 --so-pin 5678

# Generate Ed25519 key
# Note: Some SoftHSM versions may not support Ed25519
# In that case, you'll need to test with a real HSM or skip HSM tests

# List tokens
softhsm2-util --show-slots
```

### 4. Build the Project

```bash
# Build all crates
cargo build

# Run tests
cargo test --workspace

# Run with logging
RUST_LOG=debug cargo run -p sbt-notary
```

## Testing Strategy

### Unit Tests

Each crate has its own unit tests:

```bash
# Test specific crate
cargo test -p sbt-types
cargo test -p sbt-core
cargo test -p sbt-client

# Test with output
cargo test -- --nocapture
```

### Integration Tests

HSM integration tests are marked with `#[ignore]` and require a real HSM:

```bash
# Run ignored tests (requires HSM)
cargo test -- --ignored

# Run specific test
cargo test -p sbt-notary hsm::tests::test_hsm_signer -- --ignored
```

### Property-Based Tests

Core cryptographic functions use proptest:

```bash
cargo test -p sbt-core -- --include-ignored
```

## Code Quality

### Format Code

```bash
cargo fmt --all
```

### Run Linter

```bash
cargo clippy --workspace -- -D warnings
```

### Check for Security Issues

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

## Common Development Tasks

### Adding a New Message Type

1. Define in `sbt-types/src/messages.rs`
2. Add serialization tests
3. Update protocol version if breaking change

### Modifying Tree Construction

1. Edit `sbt-core/src/merkle.rs`
2. Update tests to cover new behavior
3. Ensure backward compatibility for verification

### Adding HSM Support for New Key Type

1. Update `sbt-notary/src/hsm.rs`
2. Add mechanism mapping
3. Test with your specific HSM

### Implementing Network Protocol

Current placeholder locations:
- Server: `sbt-notary/src/server.rs` (see TODO comments)
- Client: `sbt-client/src/client.rs` (see `send_request()`)

Recommended approach:
1. Define protobuf schema in `proto/`
2. Use tonic for gRPC
3. Add TLS support with mutual authentication
4. Implement retry logic with exponential backoff

## Performance Considerations

### Batch Size Tuning

- Larger batches = better amortization of signing cost
- Smaller batches = lower latency
- Monitor: requests/second, average latency, P99 latency

### Tree Construction

- Current implementation: O(n log n)
- Memory usage: ~3x the leaf count (all levels stored)
- Optimization opportunity: Streaming path generation

### HSM Performance

- Ed25519 signing: ~1000-10000 ops/sec depending on HSM
- Bottleneck: Single signing operation per batch
- Future: Consider pre-signing tree templates

## Debugging

### Enable Trace Logging

```bash
RUST_LOG=trace cargo run -p sbt-notary
```

### Debug HSM Issues

```bash
# List PKCS#11 objects
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-objects --pin 1234

# List mechanisms
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-mechanisms
```

### Verify Cryptographic Operations

```bash
# Test proof verification
cargo test -p sbt-core verify::tests -- --nocapture
```

## Contributing Checklist

Before submitting a PR:

- [ ] All tests pass: `cargo test --workspace`
- [ ] Code is formatted: `cargo fmt --all --check`
- [ ] No clippy warnings: `cargo clippy --workspace`
- [ ] Documentation updated if adding public API
- [ ] CHANGELOG.md updated
- [ ] Security implications considered

## Security Development Practices

1. **Timing-Safe Operations**: Use constant-time comparisons for secrets
2. **Secure Defaults**: Conservative security settings by default
3. **Audit Trail**: Log all security-relevant operations
4. **Input Validation**: Validate all untrusted input
5. **Fail Secure**: Errors should not leak sensitive information

## Release Process

1. Update version in workspace `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run full test suite: `cargo test --workspace --all-features`
4. Build release binaries: `cargo build --release`
5. Tag release: `git tag v0.1.0`
6. Publish crates in order: sbt-types → sbt-core → sbt-notary, sbt-client

## Resources

- [Rust Cryptography Guidelines](https://rust-lang.github.io/rust-clippy/master/index.html#crypto)
- [PKCS#11 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [Ed25519 RFC](https://datatracker.ietf.org/doc/html/rfc8032)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Stamp/Beacon Trees-types (v0.1.0)
- Core cryptographic primitives: Digest, Signature, PublicKey, Nonce, Timestamp
- Protocol message definitions: StampRequest, StampResponse, TimestampProof
- Merkle path structures and computation
- Error types for the protocol

#### Stamp/Beacon Trees-core (v0.1.0)
- Stamp/Beacon tree construction with per-leaf timing deltas
- Merkle path generation
- Cryptographic nonce generation
- Ed25519 signature verification
- Timestamp proof verification

#### Stamp/Beacon Trees-notary (v0.1.0)
- Batch processing of timestamp requests
- PKCS#11 HSM integration for Ed25519 signing
- Configurable batch parameters (size, intervals)
- TOML-based configuration
- Logging and observability hooks

#### Stamp/Beacon Trees-client (v0.1.0)
- Client library for timestamp operations
- Local proof storage using embedded database
- CLI tool with commands:
  - `timestamp`: Timestamp files or stdin data
  - `verify`: Verify timestamp proofs
  - `list`: List stored proofs
  - `show`: Display proof details
  - `export`/`import`: JSON proof exchange
- BLAKE3 hashing of client data

### Known Limitations

- Network protocol not implemented (gRPC/HTTP pending)
- No clock synchronization (relies on system clock)
- Single notary only (no federation)
- No untrusted aggregation servers
- HSM key must be pre-generated manually
- No TLS/authentication for network communication

### Security Notes

- All cryptographic operations use well-established libraries
- HSM integration prevents key extraction
- Per-leaf nonces prevent sibling attacks
- Merkle proofs enable independent verification

## [0.1.0] - TBD

Initial implementation of Stamp/Beacon Trees protocol.

[Unreleased]: https://github.com/yourusername/Stamp/Beacon Trees/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/Stamp/Beacon Trees/releases/tag/v0.1.0

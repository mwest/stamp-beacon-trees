# SBT Protocol Specification

## Overview

SBT implements the Stamp/Beacon Tree protocol for cryptographic timestamping. This document describes the protocol messages, cryptographic operations, and verification procedures.

## Protocol Version

Current version: **1**

## Message Formats

All messages use JSON serialization over the wire (gRPC/HTTP to be implemented).

### StampRequest

Client → Notary

```json
{
  "version": 1,
  "digest": "hex-encoded-32-bytes",
  "client_send_time": {
    "seconds": 1234567890,
    "nanos": 123456789
  }
}
```

**Fields:**
- `version`: Protocol version (u32)
- `digest`: Client's data hash (BLAKE3, 32 bytes, hex-encoded)
- `client_send_time`: Client's timestamp when sending request

### StampResponse

Notary → Client

```json
{
  "version": 1,
  "proof": {
    "digest": "hex-encoded-32-bytes",
    "nonce": "hex-encoded-32-bytes",
    "merkle_path": {
      "leaf_index": 0,
      "siblings": [
        {"hash": "hex-encoded-32-bytes", "is_left": false}
      ]
    },
    "delta_nanos": -100000000,
    "root_timestamp": {
      "seconds": 1234567890,
      "nanos": 123456789
    },
    "signature": "hex-encoded-64-bytes",
    "notary_pubkey": "hex-encoded-32-bytes"
  },
  "notary_send_time": {
    "seconds": 1234567890,
    "nanos": 123456789
  }
}
```

**Fields:**
- `version`: Protocol version
- `proof`: Complete timestamp proof (see below)
- `notary_send_time`: Notary's timestamp when sending response

## Timestamp Proof Structure

A timestamp proof contains everything needed for independent verification:

```rust
TimestampProof {
    digest: Digest,           // Original data hash
    nonce: Nonce,             // Unique 32-byte nonce
    merkle_path: MerklePath,  // Path to tree root
    delta_nanos: i64,         // Time delta from root (can be negative)
    root_timestamp: Timestamp, // Tree root timestamp
    signature: Signature,     // Notary's Ed25519 signature
    notary_pubkey: PublicKey, // Notary's public key
}
```

## Cryptographic Operations

### 1. Hash Function

**Algorithm**: BLAKE3
**Output**: 32 bytes
**Usage**: All hashing operations

### 2. Leaf Hash Computation

```
leaf_hash = BLAKE3(digest || nonce)
```

Where:
- `digest`: Client's 32-byte data hash
- `nonce`: Notary's 32-byte random nonce
- `||`: Concatenation

### 3. Merkle Tree Construction

**Node Hash**:
```
parent_hash = BLAKE3(left_child || right_child)
```

**Odd Number of Leaves**: Last leaf is paired with itself

**Tree Structure**:
```
         Root
        /    \
      H01    H23
     /  \   /  \
    H0  H1 H2  H3
    |   |  |   |
   L0  L1 L2  L3
```

### 4. Signature Generation

**Message to Sign**:
```
sign_message = root_hash || timestamp_seconds || timestamp_nanos
```

Where:
- `root_hash`: 32 bytes
- `timestamp_seconds`: 8 bytes (i64, big-endian)
- `timestamp_nanos`: 4 bytes (u32, big-endian)

**Total**: 44 bytes

**Algorithm**: Ed25519
**Output**: 64-byte signature

### 5. Signature Verification

```rust
verify(
    public_key: PublicKey,
    signature: Signature,
    message: sign_message
) -> Result<(), Error>
```

## Verification Procedure

To verify a timestamp proof:

1. **Compute Leaf Hash**
   ```
   leaf_hash = BLAKE3(proof.digest || proof.nonce)
   ```

2. **Compute Root Hash**
   ```
   current_hash = leaf_hash
   for each sibling in proof.merkle_path.siblings:
       if sibling.is_left:
           current_hash = BLAKE3(sibling.hash || current_hash)
       else:
           current_hash = BLAKE3(current_hash || sibling.hash)

   root_hash = current_hash
   ```

3. **Build Signature Message**
   ```
   sign_message = root_hash ||
                  proof.root_timestamp.seconds ||
                  proof.root_timestamp.nanos
   ```

4. **Verify Signature**
   ```
   ed25519_verify(
       proof.notary_pubkey,
       proof.signature,
       sign_message
   ) -> must succeed
   ```

5. **Compute Leaf Timestamp**
   ```
   leaf_timestamp = proof.root_timestamp + proof.delta_nanos
   ```

**Success**: If all steps succeed, the timestamp is valid.

## Security Properties

### Guaranteed by Protocol

1. **Existence**: Data existed before root_timestamp + delta_nanos
2. **Uniqueness**: Each leaf has a unique nonce (prevents replay)
3. **Integrity**: Merkle path ensures data hasn't been altered
4. **Non-repudiation**: Signature proves notary created the timestamp
5. **Verifiable**: Anyone with notary's public key can verify

### Timing Guarantees

Given timestamp `T` with uncertainty `ε`:

- **Leaf timestamp**: `T_leaf = T_root + Δ`
- **Valid range**: `[T_leaf - ε, T_leaf + ε]`
- **Typical ε**: ~1ms (depends on notary's clock precision)

The client's data definitely existed before `T_leaf + ε`.

## Batch Processing

Notary processes requests in batches:

1. **Accumulate**: Collect requests over time interval
2. **Assign Deltas**: Each request gets a timing delta
   - Early requests: negative delta
   - Late requests: positive delta
   - Centered around root timestamp
3. **Build Tree**: Construct Merkle tree from all leaves
4. **Sign**: Single signature for entire batch
5. **Respond**: Send each client their proof

**Benefits**:
- Single signing operation per batch
- All proofs share the same root signature
- Scalable to thousands of requests per second

## Network Protocol (TODO)

### Planned: gRPC

**Service Definition** (to be implemented):
```protobuf
service SbtNotary {
  rpc Timestamp(StampRequest) returns (StampResponse);
  rpc GetPublicKey(Empty) returns (PublicKeyResponse);
}
```

**Transport**: HTTP/2 with TLS

### Alternative: HTTP/JSON

```
POST /timestamp
Content-Type: application/json

{StampRequest JSON}

→ 200 OK
{StampResponse JSON}
```

## Error Handling

### Client Errors (4xx equivalent)
- Invalid digest length
- Invalid protocol version
- Malformed request

### Server Errors (5xx equivalent)
- HSM signing failure
- Internal server error

### Network Errors
- Timeout
- Connection refused
- TLS handshake failure

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DIGEST_LEN` | 32 | Hash output size (BLAKE3) |
| `NONCE_LEN` | 32 | Nonce size |
| `SIGNATURE_LEN` | 64 | Ed25519 signature size |
| `PUBKEY_LEN` | 32 | Ed25519 public key size |
| `PROTOCOL_VERSION` | 1 | Current protocol version |

## Example Flow

```
Client                          Notary
  |                               |
  | 1. Hash data                  |
  |    digest = BLAKE3(data)      |
  |                               |
  | 2. StampRequest               |
  |---------------------------->  |
  |    {version, digest, time}    |
  |                               |
  |                         3. Add to batch
  |                         4. Generate nonce
  |                         5. Build tree
  |                         6. Sign with HSM
  |                               |
  | 7. StampResponse              |
  | <----------------------------  |
  |    {proof, notary_time}       |
  |                               |
  | 8. Verify proof               |
  |    - Check Merkle path        |
  |    - Verify signature         |
  |    - Compute leaf timestamp   |
  |                               |
  | 9. Store proof                |
  |                               |
```

## Version Compatibility

**Breaking Changes**: Increment major version
**Non-breaking Changes**: Increment minor version

Version negotiation: Client sends version, server responds with same or error.

## References

- [Stamp/Beacon Trees](https://petertodd.org/2023/stamp-beacon-trees)
- [BLAKE3 Spec](https://github.com/BLAKE3-team/BLAKE3-specs)
- [RFC 8032: Ed25519](https://datatracker.ietf.org/doc/html/rfc8032)
- [OpenTimestamps](https://opentimestamps.org/)

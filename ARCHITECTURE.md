# Stamp/Beacon Trees Architecture

## System Overview

```
┌─────────────────┐
│  Client Apps    │
│  (timestamp     │
│   verify, etc)  │
└────────┬────────┘
         │
         │ StampRequest
         │ StampResponse
         ▼
┌─────────────────┐
│ Stamp/Beacon Trees-client   │
│  ┌───────────┐  │
│  │  Client   │  │  - Network communication
│  │  Library  │  │  - Proof verification
│  └───────────┘  │  - Storage management
│  ┌───────────┐  │
│  │  Storage  │  │
│  │  (sled)   │  │
│  └───────────┘  │
└────────┬────────┘
         │
         │ Network (gRPC/HTTP - TODO)
         │
         ▼
┌─────────────────────────────────┐
│     Stamp/Beacon Trees-notary               │
│  ┌────────────────────────┐     │
│  │  Server                │     │
│  │  - Request handling    │     │
│  │  - Response routing    │     │
│  └───────────┬────────────┘     │
│              │                  │
│              ▼                  │
│  ┌────────────────────────┐     │
│  │  Batch Processor       │     │
│  │  - Accumulate requests │     │
│  │  - Build trees         │     │
│  │  - Coordinate signing  │     │
│  └───────────┬────────────┘     │
│              │                  │
│              ▼                  │
│  ┌────────────────────────┐     │
│  │  HSM Signer            │     │
│  │  (PKCS#11)             │     │
│  └───────────┬────────────┘     │
└──────────────┼──────────────────┘
               │
               ▼
       ┌──────────────┐
       │     HSM      │
       │ (Hardware or │
       │  SoftHSM)    │
       └──────────────┘
```

## Crate Dependencies

```
Stamp/Beacon Trees-types (no dependencies)
    ↑
    ├─── Stamp/Beacon Trees-core
    │       ↑
    │       ├─── Stamp/Beacon Trees-notary
    │       │
    │       └─── Stamp/Beacon Trees-client
    │
    └─── (shared by both)
```

**Design Principle**: Dependency flows one direction, no circular dependencies.

## Data Flow: Timestamp Request

```
1. Client                    2. Notary
┌──────────────┐            ┌──────────────────┐
│ Hash Data    │            │ Receive Request  │
│ digest=H(d)  │            │ Add to Batch     │
└──────┬───────┘            └────────┬─────────┘
       │                             │
       │ StampRequest                │
       └────────────────────────────►│
                                     │
                            3. Batch Processing
                            ┌─────────────────┐
                            │ Generate Nonces │
                            │ n₀, n₁, n₂, ... │
                            └────────┬────────┘
                                     │
                            ┌────────▼────────┐
                            │ Build Tree      │
                            │  L₀ L₁ L₂ L₃    │
                            │   ╲ │  │ ╱      │
                            │    H₀₁ H₂₃      │
                            │      ╲ ╱        │
                            │      Root       │
                            └────────┬────────┘
                                     │
                            ┌────────▼────────┐
                            │ Sign with HSM   │
                            │ sig=Sign(root)  │
                            └────────┬────────┘
                                     │
       ┌─────────────────────────────┘
       │ StampResponse
       ▼
4. Client
┌──────────────┐
│ Verify Proof │
│ Store Proof  │
└──────────────┘
```

## Tree Construction Detail

```
Batch of 4 requests with timing:

Request 0: t₀ = T - 150ms  →  δ₀ = -150,000,000 ns
Request 1: t₁ = T - 50ms   →  δ₁ = -50,000,000 ns
Request 2: t₂ = T + 0ms    →  δ₂ = 0 ns
Request 3: t₃ = T + 100ms  →  δ₃ = +100,000,000 ns

Tree Structure:

         Root (T = root_timestamp)
         Hash(H₀₁ || H₂₃)
              /        \
         H₀₁           H₂₃
    Hash(L₀||L₁)   Hash(L₂||L₃)
       /    \         /    \
      L₀    L₁       L₂    L₃
      │     │        │     │
   (d₀,n₀) (d₁,n₁) (d₂,n₂) (d₃,n₃)
   δ=-150  δ=-50   δ=0    δ=+100

Where:
  Lᵢ = Hash(digest_i || nonce_i)
  T = root timestamp
  δᵢ = delta in nanoseconds
```

## Merkle Path Example

For Request 0 (left-most leaf):

```
Path to prove L₀ is in tree:

L₀ (known)
  ├─ Sibling: L₁ (is_left=false)
  └─ H₀₁ = Hash(L₀ || L₁)
       ├─ Sibling: H₂₃ (is_left=false)
       └─ Root = Hash(H₀₁ || H₂₃)

Merkle Path = [
  {hash: L₁, is_left: false},
  {hash: H₂₃, is_left: false}
]
```

Client verifies:
1. `H₀₁ = Hash(L₀ || L₁)` ✓
2. `Root = Hash(H₀₁ || H₂₃)` ✓
3. `Verify(pubkey, signature, Root || T)` ✓

## Component Interactions

### Batch Processor

```
┌─────────────────────────────────────────┐
│         Batch Processor                 │
│                                         │
│  Queue: [Req₀, Req₁, Req₂, ...]       │
│                                         │
│  Every batch_interval_ms:              │
│  1. Lock queue                          │
│  2. Take all requests                   │
│  3. Generate nonces                     │
│  4. Build tree                          │
│  5. Call HSM signer                     │
│  6. Generate responses                  │
│  7. Send to clients                     │
│                                         │
│  Channels:                              │
│    request_rx  ─►  [Process]  ─► oneshot channels
│                                         │
└─────────────────────────────────────────┘
```

### HSM Signer

```
┌─────────────────────────────────────────┐
│           HSM Signer                    │
│                                         │
│  PKCS#11 Context                       │
│    │                                    │
│    ├─► Session (logged in)             │
│    │     │                              │
│    │     ├─► Private Key Handle        │
│    │     └─► Public Key                │
│    │                                    │
│    └─► Sign(message) → signature       │
│                                         │
│  Thread-safe: Arc<HsmSigner>           │
│                                         │
└─────────────────────────────────────────┘
```

## Security Boundaries

```
┌──────────────────────────────────────────┐
│          Trusted Zone                    │
│  ┌────────────────────────────────┐     │
│  │   Notary Server Process        │     │
│  │   - Batch processing           │     │
│  │   - Tree construction          │     │
│  │   - Request validation         │     │
│  └─────────────┬──────────────────┘     │
│                │ PKCS#11                │
│  ┌─────────────▼──────────────────┐     │
│  │   HSM (Hardware/Software)      │     │
│  │   - Private key storage        │     │
│  │   - Signing operations         │     │
│  │   - Key never exported         │     │
│  └────────────────────────────────┘     │
│                                          │
│  System Clock (NTP synced)              │
└──────────────────────────────────────────┘
                 │
          Network │ (untrusted)
                 │
┌────────────────▼──────────────────────┐
│         Untrusted Zone                │
│  ┌─────────────────────────────┐     │
│  │   Clients                   │     │
│  │   - Send digests            │     │
│  │   - Receive proofs          │     │
│  │   - Verify independently    │     │
│  └─────────────────────────────┘     │
└───────────────────────────────────────┘
```

## State Management

### Notary (Stateless)

```
Current State Only:
┌────────────────────┐
│ Active Batch       │  ← In-memory only
│  - Pending requests│
│  - Being processed │
└────────────────────┘

No Historical Storage:
✗ Past proofs
✗ Request logs
✗ Tree history

Rationale: Clients store their own proofs
```

### Client (Stateful)

```
Local Database (sled):
┌────────────────────┐
│ Key: digest        │
│ Value: TimestampProof
│                    │
│ [digest₀] → proof₀ │
│ [digest₁] → proof₁ │
│ [digest₂] → proof₂ │
│     ...            │
└────────────────────┘

Directory: .Stamp/Beacon Trees/ (configurable)
```

## Configuration Flow

```
┌──────────────┐
│ notary.toml  │
└──────┬───────┘
       │
       ▼
┌──────────────────┐      ┌──────────────────┐
│ NotaryConfig     │      │ ENV: HSM_PIN     │
│  - server        │◄─────┤                  │
│  - hsm           │      └──────────────────┘
│  - batch         │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ NotaryServer     │
│  - HsmSigner     │
│  - BatchProcessor│
└──────────────────┘
```

## Future: Aggregation Layer

```
                  ┌─────────────┐
                  │   Notary    │
                  │  (Trusted)  │
                  └──────▲──────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
    ┌─────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
    │ Aggregator│  │Aggregator│  │Aggregator│
    │(Untrusted)│  │(Untrusted)│ │(Untrusted)│
    └─────▲─────┘  └────▲─────┘  └────▲─────┘
          │             │              │
      ┌───┴───┐     ┌───┴───┐      ┌───┴───┐
      │Client │     │Client │      │Client │
      └───────┘     └───────┘      └───────┘

Benefits:
- Notary handles fewer connections
- Aggregators can be geographically distributed
- Timing uncertainty adds one hop delay
```

## Performance Bottlenecks

```
Request Flow:

Network           ┌─────┐  Fast (async)
 ─────────────────►Queue│
                  └──┬──┘
                     │
Batching          ┌──▼──┐  Configurable wait
 ─────────────────►Batch│
                  └──┬──┘
                     │
Tree Building     ┌──▼──┐  O(n log n)
 ─────────────────►Build│  Fast for n<10k
                  └──┬──┘
                     │
HSM Signing       ┌──▼──┐  BOTTLENECK
 ─────────────────►Sign │  1-10k ops/sec
                  └──┬──┘
                     │
Response          ┌──▼──┐  Fast (async)
 ─────────────────►Send │
                  └─────┘

Optimization: Larger batches → fewer signatures
```

## Summary

The architecture is designed for:

- **Security**: HSM-backed, minimal trusted code
- **Scalability**: Batch processing, stateless notary
- **Verifiability**: Self-contained proofs
- **Simplicity**: Clear separation of concerns

Key insight: Single signature covers many timestamps via Merkle tree.

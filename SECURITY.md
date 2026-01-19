# Security Considerations

## Threat Model

### Assumptions

**Trusted:**
- Notary server software (auditable, open source)
- Notary's system clock (NTP-synchronized)
- HSM hardware/firmware
- Cryptographic primitives (Ed25519, BLAKE3)

**Untrusted:**
- Clients
- Network (MITM attackers possible)
- Aggregators (if implemented)

**Out of Scope:**
- Physical security of notary server
- Supply chain attacks on HSM
- Quantum computers (future threat)

## Attack Scenarios

### 1. Client Attempts to Backdate Timestamp

**Attack**: Client claims their data existed earlier than it did.

**Mitigation**:
- Notary controls all timestamps
- Client cannot influence root timestamp
- Per-leaf nonces prevent proof forgery
- Signature binds timestamp to tree root

**Status**: ✅ Mitigated by protocol design

### 2. Man-in-the-Middle Attack

**Attack**: Attacker intercepts and modifies requests/responses.

**Current Status**: ⚠️ VULNERABLE (no TLS)

**Mitigations Needed**:
- [ ] Implement TLS for all network communication
- [ ] Consider mutual TLS for authentication
- [ ] Pin notary's public key in client

**Temporary Workaround**: Run on trusted network only

### 3. Sibling Attack

**Attack**: Client with leaf₀ tries to claim they have leaf₁'s nonce.

**Mitigation**:
- Each leaf has unique nonce
- Nonces are unpredictable (crypto random)
- Client must present matching (digest, nonce) pair
- Merkle proof verification fails if nonce is wrong

**Status**: ✅ Mitigated by per-leaf nonces

### 4. Replay Attack

**Attack**: Client reuses a timestamp proof for different data.

**Mitigation**:
- Proof binds nonce to specific digest
- Changing digest breaks leaf hash
- Merkle path verification fails
- No way to forge proof for different data

**Status**: ✅ Mitigated by cryptographic binding

### 5. HSM Compromise

**Attack**: Attacker gains access to private signing key.

**Current Protections**:
- Private key never leaves HSM
- PKCS#11 API doesn't allow key export
- Signing operations logged in HSM

**Limitations**:
- If HSM is compromised, attacker can forge timestamps
- No key rotation mechanism yet
- No multi-signature scheme

**Recommendations**:
- [ ] Implement key rotation
- [ ] Use hardware HSM in production (not SoftHSM)
- [ ] Monitor HSM audit logs
- [ ] Consider threshold signatures (future)

### 6. Clock Manipulation

**Attack**: Attacker manipulates notary's system clock.

**Impact**: Timestamps would be incorrect but still valid.

**Current Status**: ⚠️ Relies on system clock

**Mitigations Needed**:
- [ ] Implement Roughtime-style clock synchronization
- [ ] Use authenticated time sources
- [ ] Detect clock jumps/anomalies
- [ ] Cross-reference with blockchain timestamps

### 7. Denial of Service

**Attack**: Flood notary with requests.

**Current Status**: ⚠️ No rate limiting

**Mitigations Needed**:
- [ ] Per-client rate limiting
- [ ] Global rate limiting
- [ ] Request size limits
- [ ] Connection limits (already configurable)
- [ ] Proof-of-work for requests (optional)

### 8. Tree Forgery

**Attack**: Create fake Merkle tree with backdated timestamp.

**Mitigation**:
- Signature verification checks:
  1. Merkle path computes to signed root ✓
  2. Signature matches notary's public key ✓
  3. Timestamp is in signed message ✓
- Cannot forge without notary's private key

**Status**: ✅ Mitigated by signature scheme

### 9. Proof Substitution

**Attack**: Replace victim's proof with different one.

**Scenario**: If proofs are transmitted insecurely.

**Mitigation**:
- Proofs are self-contained
- Verification checks digest matches
- Client can detect wrong proof immediately

**Status**: ✅ Detectable by client

### 10. Batch Timing Analysis

**Attack**: Infer information from batch timing patterns.

**Privacy Risk**: Could reveal when requests were processed together.

**Current Status**: Not addressed

**Future Consideration**:
- Randomize batch intervals
- Add dummy requests
- Constant-time batching

## Cryptographic Security

### Hash Function: BLAKE3

**Properties**:
- ✅ Collision resistance: 2^128 security
- ✅ Preimage resistance: 2^256 security
- ✅ Fast and constant-time
- ✅ No known attacks

**Usage**:
- Leaf hashing
- Merkle tree construction
- Client data hashing

### Signature: Ed25519

**Properties**:
- ✅ 128-bit security level
- ✅ Deterministic (no nonce reuse issues)
- ✅ Fast verification
- ✅ Small keys and signatures

**Usage**:
- Notary signs tree roots
- Public key distribution

**Quantum Resistance**: ❌ Not quantum-safe
- Future consideration: Post-quantum signatures

### Nonces

**Source**: `rand::thread_rng()`
**Size**: 256 bits
**Properties**: Cryptographically secure random

**Requirements**:
- ✅ Unpredictable
- ✅ Unique per leaf
- ✅ Generated server-side (clients can't choose)

## Implementation Security

### Memory Safety

**Language**: Rust
**Benefits**:
- ✅ No buffer overflows
- ✅ No use-after-free
- ✅ No data races
- ✅ Type safety

**Unsafe Usage**: Only in dependencies (audited)

### Input Validation

**Current Status**:
- ✅ Digest length validated
- ✅ Protocol version checked
- ✅ Timestamp bounds checked
- ⚠️ No request size limits
- ⚠️ No batch size enforcement

**TODO**:
- [ ] Maximum request size
- [ ] Validate all untrusted input
- [ ] Sanitize error messages (no info leaks)

### Secret Handling

**HSM PIN**:
- ✅ Read from environment variable
- ✅ Not stored in config file
- ✅ Not logged
- ⚠️ Stays in process memory

**Recommendations**:
- Use secure memory (mlock)
- Zero memory after use
- Consider pin-entry tools

### Logging

**Security-Relevant Events**:
- HSM operations
- Signature operations
- Configuration changes
- Authentication failures (when implemented)

**Log Safety**:
- ⚠️ Don't log HSM PIN
- ⚠️ Don't log private keys
- ⚠️ Don't log full request contents (PII)

## Operational Security

### Deployment Recommendations

**Notary Server**:
1. Dedicated hardware (no other services)
2. Minimal OS installation (reduce attack surface)
3. Network isolation (firewall)
4. NTP from authenticated sources
5. Automatic security updates
6. Audit logging enabled
7. Monitoring and alerting

**HSM**:
1. Hardware HSM for production (not SoftHSM)
2. Physically secured
3. Backup key material securely
4. Test disaster recovery

**Network**:
1. TLS 1.3+ only
2. Strong cipher suites
3. Certificate pinning
4. Rate limiting at edge

### Monitoring

**Key Metrics**:
- Requests per second
- Batch sizes
- Signature latency
- HSM errors
- Clock drift
- TLS handshake failures

**Alerts**:
- HSM unreachable
- Clock jump detected
- Unusual request patterns
- High error rate

### Incident Response

**If Private Key Compromised**:
1. Immediately revoke key
2. Notify all users
3. Issue new key
4. Audit all recent timestamps
5. Investigate how compromise occurred

**If Clock Manipulated**:
1. Detect via cross-referencing
2. Correct clock
3. Mark affected period
4. Notify users of uncertainty

## Client Security

### Proof Verification

**Always Verify**:
1. Merkle path computation
2. Signature validation
3. Timestamp within expected range
4. Notary public key matches known key

**Never**:
- Trust proofs without verification
- Accept proofs from untrusted sources without verification
- Skip verification for "known good" notaries

### Storage Security

**Local Database**:
- Proofs stored unencrypted (not secret data)
- Protect storage directory permissions
- Backup proofs securely

### Public Key Management

**How to Get Notary's Public Key**:
- ⚠️ Currently: Included in each proof
- Better: Pre-configured or pinned
- Best: Multiple trust anchors (DNS, transparency log)

**Recommendations**:
- [ ] Publish public key via DNS TLSA records
- [ ] Include in transparency log
- [ ] Multiple independent distribution channels

## Future Security Enhancements

### High Priority

1. **TLS Implementation**
   - Encrypt all network traffic
   - Mutual authentication option

2. **Clock Synchronization**
   - Roughtime-style secure time
   - Multiple time sources
   - Outlier detection

3. **Rate Limiting**
   - Per-client limits
   - Global limits
   - DDoS protection

### Medium Priority

4. **Key Rotation**
   - Scheduled key rotation
   - Overlap period for verification
   - Transparent to clients

5. **Transparency Log**
   - Public append-only log
   - All timestamps recorded
   - Cross-signing with other notaries

6. **Multi-Signature**
   - Threshold signatures
   - Multiple HSMs
   - Fault tolerance

### Low Priority

7. **Post-Quantum Cryptography**
   - Hybrid signatures (Ed25519 + PQ)
   - Future-proof against quantum attacks

8. **Hardware Security**
   - TPM integration
   - Secure boot
   - Attestation

## Security Audit Recommendations

Before production deployment:

1. **Code Audit**:
   - [ ] External security review
   - [ ] Fuzzing of input parsers
   - [ ] Static analysis (cargo-audit, clippy)

2. **Cryptographic Review**:
   - [ ] Verify correct use of primitives
   - [ ] Check for timing side-channels
   - [ ] Validate random number generation

3. **Operational Review**:
   - [ ] Deployment procedures
   - [ ] Key management
   - [ ] Incident response plan

4. **Penetration Testing**:
   - [ ] Network security
   - [ ] API security
   - [ ] HSM integration

## Responsible Disclosure

If you discover a security issue:

1. **DO NOT** disclose publicly
2. Email: security@example.com (TODO: set up)
3. Use PGP if possible (TODO: publish key)
4. Provide details and reproduction steps
5. Allow 90 days for fix before disclosure

## Security Checklist

Before deploying to production:

- [ ] TLS enabled and configured
- [ ] HSM is hardware (not SoftHSM)
- [ ] Rate limiting implemented
- [ ] Monitoring and alerting configured
- [ ] Security audit completed
- [ ] Incident response plan documented
- [ ] Key backup and recovery tested
- [ ] Clock synchronization verified
- [ ] Access controls configured
- [ ] Logs reviewed and secured

## Conclusion

The current implementation provides strong cryptographic security but lacks operational security features (TLS, rate limiting, clock sync).

**Current Status**: Suitable for testing and development only.

**Production Readiness**: Requires implementation of TODO items above.

**Contact**: For security questions or concerns, file an issue or contact the maintainers.

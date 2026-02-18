# Certificate Management Guide

This document covers TLS certificate generation, configuration, and management for SBT notary deployments.

## Quick Start

```bash
# Generate CA + server certificates for local development
./scripts/generate-certs.sh ./certs

# Start server with TLS
sbt-notary --config notary.toml
# (add [tls] section pointing to ./certs/server.crt and server.key)

# Connect client with CA cert
sbt --server https://localhost:8080 --ca-cert ./certs/ca.crt timestamp myfile.txt
```

## Certificate Generation

### Using the Script

The `scripts/generate-certs.sh` script generates a self-signed CA, server certificate, and optional client certificate using EC P-256 keys.

```bash
# Basic usage (generates CA + server cert in ./certs/)
./scripts/generate-certs.sh .

# With client cert for mTLS
./scripts/generate-certs.sh . --client

# Custom validity and SANs
./scripts/generate-certs.sh . --days 730 --server-san notary.example.com

# All options
./scripts/generate-certs.sh ./deploy/certs \
    --days 365 \
    --server-san notary.example.com \
    --server-san 192.168.1.100 \
    --client \
    --ca-cn "My Org CA" \
    --server-cn notary.example.com \
    --client-cn my-client
```

**Generated files:**

| File | Description |
|------|-------------|
| `ca.key` | CA private key (keep secure!) |
| `ca.crt` | CA certificate (distribute to clients) |
| `server.key` | Server private key |
| `server.crt` | Server certificate (signed by CA) |
| `client.key` | Client private key (mTLS only) |
| `client.crt` | Client certificate (mTLS only) |

The script also prints the server's SPKI pin (SHA-256, base64) for certificate pinning.

### Manual Generation (OpenSSL)

If you prefer manual control:

```bash
# 1. Generate CA
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=SBT CA"

# 2. Generate server key and CSR
openssl ecparam -genkey -name prime256v1 -noout -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

# 3. Sign server cert with SANs
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# 4. Compute SPKI pin
openssl x509 -in server.crt -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64
```

### Let's Encrypt (Production)

For production deployments with a public domain:

```bash
# Using certbot
certbot certonly --standalone -d notary.example.com

# Certificates will be in /etc/letsencrypt/live/notary.example.com/
# fullchain.pem = server cert + intermediate
# privkey.pem   = server private key
```

Configure in `notary.toml`:
```toml
[tls]
cert_path = "/etc/letsencrypt/live/notary.example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/notary.example.com/privkey.pem"
```

## Server Configuration

### TLS Section in `notary.toml`

```toml
[tls]
# Server certificate and key (required for TLS)
cert_path = "/etc/sbt/server.crt"
key_path = "/etc/sbt/server.key"

# CA certificate for client verification (optional, enables mTLS)
# When set, clients must present certificates signed by this CA
# ca_cert_path = "/etc/sbt/ca.crt"

# Require client certificates (mTLS)
# Only applies when ca_cert_path is set
# require_client_cert = true
```

## Client Configuration

### CLI Flags

| Flag | Description |
|------|-------------|
| `--ca-cert PATH` | CA certificate for server verification |
| `--client-cert PATH` | Client certificate for mTLS |
| `--client-key PATH` | Client private key for mTLS |
| `--tls-pin PIN` | SPKI pin (base64-encoded SHA-256) |

### Examples

```bash
# Basic TLS (CA cert for server verification)
sbt --server https://notary.example.com:8080 \
    --ca-cert ca.crt \
    timestamp myfile.txt

# TLS with certificate pinning
sbt --server https://notary.example.com:8080 \
    --ca-cert ca.crt \
    --tls-pin "dGhpcyBpcyBhIHRlc3QgcGlu..." \
    timestamp myfile.txt

# mTLS (mutual TLS)
sbt --server https://notary.example.com:8080 \
    --ca-cert ca.crt \
    --client-cert client.crt \
    --client-key client.key \
    timestamp myfile.txt
```

## Certificate Pinning

SBT supports two independent pinning mechanisms:

### 1. TLS Certificate Pinning (Transport Layer)

Pins the server's TLS certificate by its SPKI (Subject Public Key Info) hash, following the RFC 7469 approach. This prevents MITM attacks even if a CA is compromised.

**How it works:**
- Client computes SHA-256 of the server certificate's SPKI during TLS handshake
- Compared against the expected pin provided via `--tls-pin`
- Connection rejected if pin doesn't match

**Computing the pin:**
```bash
# Using the generation script (printed automatically)
./scripts/generate-certs.sh ./certs

# Using openssl
openssl x509 -in server.crt -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64

# Programmatically (Rust)
use sbt_client::compute_spki_pin_from_pem;
let pin = compute_spki_pin_from_pem(cert_pem_bytes)?;
```

### 2. Application-Level Key Pinning (Notary Layer)

Pins the notary's Ed25519 signing key (distinct from TLS certificate). Available via the `PinMode` API:

- **None**: Accept any notary key
- **TrustOnFirstUse (TOFU)**: Pin the key from first response
- **Pinned**: Pre-configured expected key

### When to Use Each

| Scenario | TLS Pin | App Pin |
|----------|---------|---------|
| Prevent MITM on network | Yes | No |
| Prevent notary key swap | No | Yes |
| Production deployment | Recommended | Recommended |
| Development/testing | Optional | Optional |

## Certificate Rotation

### Same Key, New Certificate

When renewing a certificate with the same key pair (e.g., Let's Encrypt renewal):

1. The SPKI pin **remains valid** (pin is based on public key, not cert)
2. Replace cert files and restart server
3. No client configuration changes needed

### New Key, New Certificate

When rotating to a new key pair:

1. The old SPKI pin **becomes invalid**
2. Compute new pin from new certificate
3. Update all clients with new `--tls-pin` value
4. Consider a transition period with both old and new certs

**Rotation procedure:**
```bash
# 1. Generate new certs (keeps same CA)
./scripts/generate-certs.sh ./new-certs --ca-cn "Same CA"

# 2. Note the new SPKI pin from script output

# 3. Update server config to use new certs
# 4. Restart server

# 5. Update client --tls-pin values
```

## mTLS Setup

Mutual TLS requires both server and client to present certificates.

### Step-by-Step

1. **Generate certificates with client cert:**
   ```bash
   ./scripts/generate-certs.sh ./certs --client
   ```

2. **Configure server:**
   ```toml
   [tls]
   cert_path = "./certs/server.crt"
   key_path = "./certs/server.key"
   ca_cert_path = "./certs/ca.crt"    # Enables client cert verification
   ```

3. **Connect client with cert:**
   ```bash
   sbt --server https://localhost:8080 \
       --ca-cert ./certs/ca.crt \
       --client-cert ./certs/client.crt \
       --client-key ./certs/client.key \
       timestamp myfile.txt
   ```

4. **Combine with authentication:**
   ```toml
   [auth]
   mode = "hybrid"  # Accept API key OR mTLS certificate
   ```

## Troubleshooting

### Common Errors

**"Failed to connect with TLS: transport error"**
- Verify the server is running with TLS enabled
- Check that `--ca-cert` points to the correct CA that signed the server cert
- Verify server cert SANs include the hostname you're connecting to

**"TLS certificate SPKI pin mismatch"**
- The server certificate's public key doesn't match the expected pin
- Recompute the pin from the current server certificate
- This is expected after key rotation

**"certificate verify failed"**
- The CA certificate doesn't match the server's signing CA
- Check certificate chain: server cert must be signed by the provided CA

**"connection refused" with TLS**
- Server may not have TLS enabled (check `[tls]` section in config)
- Use `https://` scheme in the server URL

**"Connecting to HTTPS without TLS enabled"**
- The client URL uses `https://` but no TLS options are configured
- Add `--ca-cert` flag or configure TLS options

### Verifying Certificates

```bash
# Check certificate details
openssl x509 -in server.crt -text -noout

# Verify certificate chain
openssl verify -CAfile ca.crt server.crt

# Check certificate expiry
openssl x509 -in server.crt -enddate -noout

# Test TLS connection
openssl s_client -connect localhost:8080 -CAfile ca.crt
```

## Security Recommendations

1. **Protect private keys**: Restrict file permissions (`chmod 600 *.key`)
2. **Rotate certificates**: Before expiry, ideally annually for self-signed
3. **Use certificate pinning**: Especially for production client deployments
4. **Monitor certificate expiry**: Set up alerts before certificates expire
5. **Use Let's Encrypt for production**: Automated renewal, trusted CA
6. **Enable mTLS for sensitive deployments**: Authenticate both client and server

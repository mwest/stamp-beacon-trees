#!/usr/bin/env bash
#
# Generate TLS certificates for SBT notary server and client.
#
# Creates a self-signed CA, server certificate (signed by CA), and
# optional client certificate (for mTLS). Uses EC P-256 keys.
#
# Usage:
#   ./scripts/generate-certs.sh [OUTPUT_DIR] [OPTIONS]
#
# Options:
#   --days DAYS         Certificate validity in days (default: 365)
#   --server-san SAN    Additional server SAN (can be repeated)
#   --client            Also generate a client certificate for mTLS
#   --ca-cn NAME        CA common name (default: "SBT Test CA")
#   --server-cn NAME    Server common name (default: "localhost")
#   --client-cn NAME    Client common name (default: "sbt-client")
#
# Examples:
#   ./scripts/generate-certs.sh ./certs
#   ./scripts/generate-certs.sh ./certs --client --days 730
#   ./scripts/generate-certs.sh ./certs --server-san "notary.example.com"

set -euo pipefail

# Defaults
OUTPUT_DIR="${1:-.}/certs"
DAYS=365
CA_CN="SBT Test CA"
SERVER_CN="localhost"
CLIENT_CN="sbt-client"
GENERATE_CLIENT=false
EXTRA_SANS=()

# Parse arguments (skip first positional arg if it doesn't start with --)
shift 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days)       DAYS="$2"; shift 2 ;;
        --server-san) EXTRA_SANS+=("$2"); shift 2 ;;
        --client)     GENERATE_CLIENT=true; shift ;;
        --ca-cn)      CA_CN="$2"; shift 2 ;;
        --server-cn)  SERVER_CN="$2"; shift 2 ;;
        --client-cn)  CLIENT_CN="$2"; shift 2 ;;
        *)            echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check for openssl
if ! command -v openssl &>/dev/null; then
    echo "Error: openssl is required but not found in PATH."
    echo "Install it via your package manager or Git for Windows."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo "Generating certificates in: $OUTPUT_DIR"
echo "Validity: $DAYS days"
echo

# Build SAN list for server cert
SAN_LIST="DNS:localhost,IP:127.0.0.1"
for san in "${EXTRA_SANS[@]:-}"; do
    if [[ -n "$san" ]]; then
        # Auto-detect IP vs DNS
        if [[ "$san" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            SAN_LIST="$SAN_LIST,IP:$san"
        else
            SAN_LIST="$SAN_LIST,DNS:$san"
        fi
    fi
done

# === 1. Generate CA ===
echo "=== Generating CA ==="
openssl ecparam -genkey -name prime256v1 -noout -out "$OUTPUT_DIR/ca.key" 2>/dev/null
openssl req -new -x509 -key "$OUTPUT_DIR/ca.key" -out "$OUTPUT_DIR/ca.crt" \
    -days "$DAYS" -subj "/CN=$CA_CN" -sha256 2>/dev/null
echo "  CA key:  $OUTPUT_DIR/ca.key"
echo "  CA cert: $OUTPUT_DIR/ca.crt"
echo

# === 2. Generate Server Certificate ===
echo "=== Generating Server Certificate ==="
echo "  SANs: $SAN_LIST"

openssl ecparam -genkey -name prime256v1 -noout -out "$OUTPUT_DIR/server.key" 2>/dev/null
openssl req -new -key "$OUTPUT_DIR/server.key" -out "$OUTPUT_DIR/server.csr" \
    -subj "/CN=$SERVER_CN" -sha256 2>/dev/null

# Sign with CA, including SANs
openssl x509 -req -in "$OUTPUT_DIR/server.csr" \
    -CA "$OUTPUT_DIR/ca.crt" -CAkey "$OUTPUT_DIR/ca.key" -CAcreateserial \
    -out "$OUTPUT_DIR/server.crt" -days "$DAYS" -sha256 \
    -extfile <(printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" "$SAN_LIST") \
    2>/dev/null

rm -f "$OUTPUT_DIR/server.csr" "$OUTPUT_DIR/ca.srl"
echo "  Server key:  $OUTPUT_DIR/server.key"
echo "  Server cert: $OUTPUT_DIR/server.crt"
echo

# === 3. Generate Client Certificate (optional) ===
if [[ "$GENERATE_CLIENT" == true ]]; then
    echo "=== Generating Client Certificate ==="

    openssl ecparam -genkey -name prime256v1 -noout -out "$OUTPUT_DIR/client.key" 2>/dev/null
    openssl req -new -key "$OUTPUT_DIR/client.key" -out "$OUTPUT_DIR/client.csr" \
        -subj "/CN=$CLIENT_CN" -sha256 2>/dev/null

    openssl x509 -req -in "$OUTPUT_DIR/client.csr" \
        -CA "$OUTPUT_DIR/ca.crt" -CAkey "$OUTPUT_DIR/ca.key" -CAcreateserial \
        -out "$OUTPUT_DIR/client.crt" -days "$DAYS" -sha256 \
        -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth") \
        2>/dev/null

    rm -f "$OUTPUT_DIR/client.csr" "$OUTPUT_DIR/ca.srl"
    echo "  Client key:  $OUTPUT_DIR/client.key"
    echo "  Client cert: $OUTPUT_DIR/client.crt"
    echo
fi

# === 4. Compute SPKI Pin ===
SPKI_PIN=$(openssl x509 -in "$OUTPUT_DIR/server.crt" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64)

echo "=== Certificate Summary ==="
echo
echo "Files generated:"
echo "  CA:     $OUTPUT_DIR/ca.key, $OUTPUT_DIR/ca.crt"
echo "  Server: $OUTPUT_DIR/server.key, $OUTPUT_DIR/server.crt"
if [[ "$GENERATE_CLIENT" == true ]]; then
    echo "  Client: $OUTPUT_DIR/client.key, $OUTPUT_DIR/client.crt"
fi
echo
echo "Server SPKI pin (SHA-256, base64):"
echo "  $SPKI_PIN"
echo
echo "=== Example Commands ==="
echo
echo "Start notary server with TLS:"
echo "  sbt-notary --config notary.toml"
echo "  # Add to notary.toml:"
echo "  # [tls]"
echo "  # cert_path = \"$OUTPUT_DIR/server.crt\""
echo "  # key_path = \"$OUTPUT_DIR/server.key\""
if [[ "$GENERATE_CLIENT" == true ]]; then
    echo "  # ca_cert_path = \"$OUTPUT_DIR/ca.crt\"  # Enable mTLS"
fi
echo
echo "Connect client with TLS:"
echo "  sbt --server https://localhost:8080 --ca-cert $OUTPUT_DIR/ca.crt timestamp <file>"
echo
echo "Connect client with TLS + certificate pinning:"
echo "  sbt --server https://localhost:8080 --ca-cert $OUTPUT_DIR/ca.crt --tls-pin \"$SPKI_PIN\" timestamp <file>"
if [[ "$GENERATE_CLIENT" == true ]]; then
    echo
    echo "Connect client with mTLS:"
    echo "  sbt --server https://localhost:8080 --ca-cert $OUTPUT_DIR/ca.crt \\"
    echo "      --client-cert $OUTPUT_DIR/client.crt --client-key $OUTPUT_DIR/client.key timestamp <file>"
fi

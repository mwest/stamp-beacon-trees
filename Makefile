.PHONY: help build test clean fmt lint audit check run-notary run-client example

help:
	@echo "Stamp/Beacon Trees Development Commands"
	@echo "==========================="
	@echo ""
	@echo "  make build       - Build all crates"
	@echo "  make test        - Run all tests"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make fmt         - Format code"
	@echo "  make lint        - Run clippy"
	@echo "  make audit       - Check for security issues"
	@echo "  make check       - Run all checks (fmt, lint, test)"
	@echo "  make example     - Run basic usage example"
	@echo "  make run-notary  - Run notary server"
	@echo "  make run-client  - Run client CLI"
	@echo ""

build:
	cargo build --workspace

build-release:
	cargo build --workspace --release

test:
	cargo test --workspace

test-verbose:
	cargo test --workspace -- --nocapture

clean:
	cargo clean

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

lint:
	cargo clippy --workspace -- -D warnings

audit:
	cargo audit

check: fmt-check lint test
	@echo "✓ All checks passed"

example:
	cargo run --example basic_usage

run-notary:
	cargo run -p sbt-notary

run-client:
	cargo run -p sbt-client -- --help

# Development setup
setup-softhsm:
	@echo "Setting up SoftHSM for development..."
	softhsm2-util --init-token --slot 0 --label "sbt-test" --pin 1234 --so-pin 5678
	@echo "✓ SoftHSM initialized"

# Release tasks
release-check: check
	@echo "Checking release readiness..."
	cargo build --release
	@echo "✓ Release builds successfully"

# Documentation
doc:
	cargo doc --workspace --no-deps --open

doc-private:
	cargo doc --workspace --document-private-items --no-deps --open

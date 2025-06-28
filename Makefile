.PHONY: build test clean install run dev release

# Build the project
build:
	cargo build

# Build for release
release:
	cargo build --release

# Run tests
test:
	cargo test

# Run with verbose test output
test-verbose:
	cargo test -- --nocapture

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/

# Install locally
install: release
	cargo install --path .

# Run the server
run:
	cargo run

# Development mode with auto-reload
dev:
	cargo watch -x run

# Format code
fmt:
	cargo fmt

# Check code
check:
	cargo check
	cargo clippy -- -D warnings

# Build for all targets
build-all:
	cargo build --target x86_64-apple-darwin
	cargo build --target aarch64-apple-darwin

# Create universal binary for macOS
universal-binary: build-all
	mkdir -p target/universal-apple-darwin/release
	lipo -create \
		target/x86_64-apple-darwin/release/ssh-client-mcp \
		target/aarch64-apple-darwin/release/ssh-client-mcp \
		-output target/universal-apple-darwin/release/ssh-client-mcp

# Package for distribution
package: release
	mkdir -p dist
	cp target/release/ssh-client-mcp dist/
	cp README.md dist/
	cp CREDENTIAL_SECURITY.md dist/
	cd dist && tar -czf ssh-client-mcp.tar.gz *
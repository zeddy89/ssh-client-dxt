# SSH Client MCP Server (Rust Implementation)

A secure SSH client implemented as a Model Context Protocol (MCP) server in Rust, providing enhanced security, performance, and reliability.

## Features

### 🔒 Security First
- **Zero Credential Exposure**: Claude never sees passwords or private keys
- **Reference-Based Authentication**: Credentials stored securely with UUID references
- **Memory-Safe Implementation**: Rust's ownership system prevents common vulnerabilities
- **Secure Input Methods**: Terminal-based credential entry outside MCP protocol

### 🚀 Performance
- **Native Performance**: Compiled Rust binary with minimal overhead
- **Async/Await**: Non-blocking I/O for concurrent operations
- **Efficient Memory Usage**: Zero-copy operations where possible
- **Fast Startup**: No runtime dependencies or interpreters

### 🛠 Functionality
- Full SSH protocol support via native `ssh2` library
- Concurrent session management with configurable limits
- SFTP file transfers (upload/download)
- Port forwarding (local and remote)
- Host key verification and management
- Credential storage with OS keychain integration
- Comprehensive audit logging
- Session timeout and cleanup

## Installation

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- macOS, Linux, or Windows with OpenSSH

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd ssh-client-dxt

# Build release binary
make release

# Or using cargo directly
cargo build --release
```

### Installing

```bash
# Install locally
make install

# Or copy binary manually
cp target/release/ssh-client-mcp /usr/local/bin/
```

## Usage

### Starting the Server

```bash
# Run directly
./target/release/ssh-client-mcp

# Or if installed
ssh-client-mcp
```

### Environment Variables

- `MAX_SESSIONS`: Maximum concurrent SSH sessions (default: 10)
- `SESSION_TIMEOUT`: Session timeout in seconds (default: 1800)
- `ENABLE_AUDIT_LOGGING`: Enable audit logging (default: false)
- `AUDIT_LOG_PATH`: Path to audit log file
- `RUST_LOG`: Logging level (trace, debug, info, warn, error)

## MCP Tools

### 1. `ssh_credential_store`
Store credentials securely without exposing them to Claude.

```json
{
  "tool": "ssh_credential_store",
  "arguments": {
    "action": "store",
    "credentialType": "password",
    "description": "Production server password"
  }
}
```

### 2. `ssh_connect`
Connect to SSH server using credentials or credential references.

```json
{
  "tool": "ssh_connect",
  "arguments": {
    "host": "example.com",
    "port": 22,
    "username": "admin",
    "passwordRef": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### 3. `ssh_execute`
Execute commands on remote server.

```json
{
  "tool": "ssh_execute",
  "arguments": {
    "sessionId": "session-uuid",
    "command": "ls -la /var/log"
  }
}
```

### 4. `ssh_upload_file` / `ssh_download_file`
Transfer files via SFTP.

```json
{
  "tool": "ssh_upload_file",
  "arguments": {
    "sessionId": "session-uuid",
    "localPath": "/local/file.txt",
    "remotePath": "/remote/file.txt"
  }
}
```

### 5. `ssh_port_forward`
Set up port forwarding.

```json
{
  "tool": "ssh_port_forward",
  "arguments": {
    "sessionId": "session-uuid",
    "localPort": 8080,
    "remoteHost": "localhost",
    "remotePort": 80,
    "type": "local"
  }
}
```

## Security Best Practices

### Credential Management
1. Always use `ssh_credential_store` for passwords
2. Use SSH keys with `ssh_credential_store` for passphrases
3. Never pass credentials directly in tool arguments
4. Regularly rotate stored credentials

### Session Security
1. Disconnect sessions when not in use
2. Monitor active sessions with `ssh_list_sessions`
3. Set appropriate session timeouts
4. Review audit logs regularly

### Host Verification
1. Always verify host fingerprints on first connection
2. Use `ssh_verify_host` to manage known hosts
3. Investigate any host key changes

## Development

### Running Tests

```bash
# Run all tests
make test

# Run with output
make test-verbose

# Run specific test
cargo test test_credential_store
```

### Code Quality

```bash
# Format code
make fmt

# Run linter and checks
make check
```

### Building for Multiple Platforms

```bash
# Build universal macOS binary
make universal-binary

# Cross-compile for Linux
cargo build --target x86_64-unknown-linux-gnu
```

## Architecture

### Core Components

1. **MCP Server** (`mcp_server.rs`)
   - JSON-RPC protocol implementation
   - Tool and prompt registration
   - Request routing

2. **Session Manager** (`session_manager.rs`)
   - Concurrent session handling
   - Timeout management
   - Resource cleanup

3. **SSH Client** (`ssh_client.rs`)
   - SSH protocol operations
   - Authentication handling
   - Command execution

4. **Credential Provider** (`credential_provider.rs`)
   - Secure credential storage
   - Reference management
   - Type validation

### Security Model

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Claude    │────▶│  MCP Server  │────▶│ SSH Sessions │
└─────────────┘     └──────────────┘     └──────────────┘
       │                    │                     │
       │              ┌─────▼──────┐             │
       └─ Sees Only ─▶│ Reference  │             │
         References   │    IDs     │             │
                      └─────┬──────┘             │
                            │                     │
                      ┌─────▼──────┐             │
                      │ Credential │◀────────────┘
                      │  Provider  │  Actual Creds
                      └────────────┘
```

## Troubleshooting

### Common Issues

1. **Build Failures**
   - Ensure Rust 1.70+ is installed
   - Check OpenSSL development headers are available
   - Run `cargo update` to update dependencies

2. **Connection Issues**
   - Verify SSH service is running on target
   - Check firewall rules
   - Test with native SSH client first

3. **Credential Issues**
   - Ensure terminal has focus during credential prompt
   - Check credential type matches authentication method
   - Verify reference IDs are correct

### Debug Logging

Enable detailed logging:
```bash
RUST_LOG=debug ssh-client-mcp
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Built with [ssh2-rs](https://github.com/alexcrichton/ssh2-rs)
- MCP protocol by Anthropic
- Secure credential handling inspired by 1Password CLI
# SSH Client MCP Server (Rust Implementation)

A security-focused SSH client implemented as a Model Context Protocol (MCP) server, now in Rust with **true credential isolation**.

## 🔐 True Credential Isolation

This implementation features a groundbreaking security approach:
- **Zero Credential Exposure**: Your passwords and private keys NEVER pass through the AI conversation
- **External Credential Management**: Credentials are stored using a separate CLI tool (`ssh-creds`)
- **Reference-Based Access**: Only secure UUID references are shared with the AI
- **Local Storage**: All credentials stored locally with proper file permissions (600)

## Features

### Security Features
- **True Credential Isolation**: External credential storage via `ssh-creds` CLI tool
- **Reference-Based Authentication**: AI only sees UUID references, never actual credentials
- **Host Key Verification**: Validates SSH host keys with fingerprint checking
- **Session Management**: Automatic timeout and secure cleanup
- **Memory Safety**: Implemented in Rust for maximum security
- **No Credential Persistence in AI Context**: Credentials exist only in your secure local storage

### Supported Operations
- SSH connection management (password and key-based auth)
- Command execution with output capture
- SFTP file upload/download
- Port forwarding (local and remote)
- Session listing and management
- Host key verification
- Configuration management

## Installation

### Prerequisites
- Rust toolchain (for building from source)
- Claude Desktop or compatible MCP client

### Quick Start

1. Clone and build:
```bash
git clone https://github.com/yourusername/ssh-client-dxt.git
cd ssh-client-dxt
cargo build --release
```

2. Configure Claude Desktop:
Add to your Claude Desktop configuration:
```json
{
  "ssh-client": {
    "command": "/path/to/ssh-client-dxt/target/release/ssh-client-mcp",
    "args": []
  }
}
```

## 🔑 Secure Credential Management

### The ssh-creds Tool

Store credentials securely OUTSIDE of the AI conversation:

```bash
# Store a password
./ssh-creds store
# Choose option 1 (Password)
# Enter username and password
# Receive a reference ID like: ref_abc123...

# List stored credentials
./ssh-creds list

# Delete a credential
./ssh-creds delete
```

### Using Credentials in Claude

Once you have a reference ID from `ssh-creds`, use it in Claude:

```
Use ssh_connect with:
- host: "example.com"
- credentialRef: "ref_abc123..."
```

The AI never sees your actual credentials!

## Usage Examples

### Secure Connection (Recommended)
```
1. First, in your terminal:
   $ ./ssh-creds store
   (follow prompts, get reference ID)

2. Then in Claude:
   Use ssh_connect with:
   - host: "example.com"
   - credentialRef: "ref_your_id_here"
```

### Execute Commands
```
Use ssh_execute with:
- sessionId: "session-id-from-connect"
- command: "ls -la"
```

### File Transfer
```
Use ssh_upload_file with:
- sessionId: "session-id"
- localPath: "/path/to/local/file"
- remotePath: "/path/to/remote/file"
```

## Available Tools

1. **ssh_connect** - Establish SSH connections
2. **ssh_execute** - Run commands on remote servers
3. **ssh_disconnect** - Close SSH sessions
4. **ssh_list_sessions** - View active sessions
5. **ssh_upload_file** - Upload files via SFTP
6. **ssh_download_file** - Download files via SFTP
7. **ssh_port_forward** - Set up port forwarding
8. **ssh_manage_keys** - Manage SSH keys (deprecated - use ssh-creds)
9. **ssh_verify_host** - Verify host fingerprints
10. **ssh_config_manage** - Save/load connection configurations
11. **ssh_credential_store** - (DEPRECATED - use ssh-creds CLI instead)

## Security Best Practices

1. **Always use ssh-creds** for credential storage
2. **Never type passwords or keys** in the Claude conversation
3. **Verify host fingerprints** on first connection
4. **Use SSH keys** instead of passwords when possible
5. **Review stored credentials** regularly with `ssh-creds list`
6. **Delete unused credentials** with `ssh-creds delete`

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Claude    │────▶│  MCP Server  │────▶│ SSH Session │
│     AI      │     │    (Rust)    │     │  Management │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Credential  │
                    │  References  │
                    └──────────────┘
                           │
                           ▼
┌─────────────┐     ┌──────────────┐
│  Terminal   │────▶│  ssh-creds   │────▶ ~/.ssh-mcp/
│    User     │     │   CLI Tool   │      credentials/
└─────────────┘     └──────────────┘      (secure storage)
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ssh-client-dxt.git
cd ssh-client-dxt

# Build release binary
cargo build --release

# The binary will be at:
# target/release/ssh-client-mcp
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## Security

- Report security vulnerabilities privately via GitHub Security Advisories
- See [SECURITY.md](./SECURITY.md) for our security policy
- Review [SSH-CREDS-README.md](./SSH-CREDS-README.md) for credential security details

## License

MIT License - See [LICENSE](./LICENSE) file for details

## Acknowledgments

- Built on the Model Context Protocol specification
- Uses the `ssh2` crate for SSH operations
- Inspired by security-first design principles
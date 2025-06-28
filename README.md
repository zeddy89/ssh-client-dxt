# SSH Client MCP Server

A secure SSH client implementation for the Model Context Protocol (MCP) with encrypted credential storage.

## Features

- 🔐 **Encrypted Credentials**: AES-256-GCM encryption with Argon2 key derivation
- 🌍 **Cross-Platform**: Native support for Windows, macOS, and Linux
- 🤖 **Zero Exposure**: Credentials never visible to AI assistants
- ⚡ **High Performance**: Built with Rust for speed and safety
- 🔑 **Secure Storage**: Integration with OS-native credential managers

## Installation

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- OpenSSL development libraries
- Platform-specific requirements:
  - **macOS**: Xcode Command Line Tools
  - **Linux**: `libssl-dev`, `pkg-config`, `libsecret-1-dev`
  - **Windows**: Visual Studio Build Tools

### Build from Source

```bash
git clone https://github.com/yourusername/ssh-client-mcp.git
cd ssh-client-mcp
cargo build --release
```

Binaries will be available in `target/release/`:
- `ssh-client-mcp` - Main MCP server
- `ssh-creds` - Credential management tool
- `ssh-creds-gui` - GUI helper for credential storage

## Quick Start

### 1. Store Master Password

```bash
# Interactive GUI (recommended)
./target/release/ssh-creds-gui

# Or use platform-specific commands:
# macOS
security add-generic-password -a "ssh-mcp" -s "master-password" -w "YourPassword"

# Windows
cmdkey /add:ssh-mcp /user:master-password /pass:YourPassword

# Linux
secret-tool store --label="SSH MCP Master Password" service ssh-mcp username master-password
```

### 2. Store SSH Credentials

```bash
./target/release/ssh-creds store
# Follow prompts to enter credentials
```

### 3. Configure Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "ssh-client": {
      "command": "/path/to/ssh-client-mcp/scripts/[platform]-wrapper.sh",
      "args": []
    }
  }
}
```

Where `[platform]` is one of: `macos`, `linux`, `windows`

## Usage

In Claude Desktop, you can use commands like:

```
Connect to SSH server example.com using credentialRef "ref_abc123..."
Execute "ls -la" on the SSH session
Upload file.txt to /remote/path/
Download /remote/file.txt to local path
```

## Tools Available

The MCP server provides these tools:
- `ssh_connect` - Connect to SSH servers
- `ssh_execute` - Execute commands
- `ssh_disconnect` - Close connections
- `ssh_upload_file` - Upload files via SFTP
- `ssh_download_file` - Download files via SFTP
- `ssh_port_forward` - Set up port forwarding
- `ssh_config_manage` - Manage saved configurations

## Security

- Credentials are encrypted at rest using AES-256-GCM
- Master passwords are never stored in plain text
- Integration with OS-native secure storage (Keychain, Credential Manager, Secret Service)
- All connections use SSH2 protocol with modern ciphers

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## Support

For issues and feature requests, please use the GitHub issue tracker.
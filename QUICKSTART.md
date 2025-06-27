# Quick Start Guide - Secure SSH Client MCP

## Installation Steps

1. **Install Node.js dependencies**:
   ```bash
   cd ssh-client-dxt
   npm install
   ```

2. **Build the DXT package**:
   ```bash
   npm run build
   ```
   This creates a `secure-ssh-client.dxt` file.

3. **Install in Claude Desktop**:
   - Open Claude Desktop settings
   - Navigate to Extensions/MCP Servers
   - Click "Install from file"
   - Select the generated `.dxt` file

## First Connection

1. **Connect to a server**:
   ```
   Use ssh_connect tool:
   - host: "your-server.com"
   - username: "your-username"  
   - password: "your-password"
   - storeCredentials: true (to save password securely)
   ```

2. **Execute a command**:
   ```
   Use ssh_execute tool:
   - sessionId: (from connect response)
   - command: "ls -la"
   ```

3. **Disconnect when done**:
   ```
   Use ssh_disconnect tool:
   - sessionId: (your session ID)
   ```

## Security Notes

- Credentials are stored in your OS keychain (secure)
- All operations are logged to `~/.ssh-mcp-audit.log`
- Host keys are verified automatically
- Sessions timeout after 30 minutes of inactivity

## Common Use Cases

### File Transfer
- Upload: Use `ssh_upload_file` tool
- Download: Use `ssh_download_file` tool

### Port Forwarding
- Use `ssh_port_forward` tool for local port forwarding

### Multiple Sessions
- Connect to multiple servers simultaneously (max 5 by default)
- List active sessions with `ssh_list_sessions`

## Troubleshooting

- **Connection refused**: Check if SSH service is running on target
- **Authentication failed**: Verify credentials or try key-based auth
- **Host key verification failed**: New host or key changed - verify with admin
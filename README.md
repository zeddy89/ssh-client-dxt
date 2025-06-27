# Secure SSH Client MCP Server

A security-focused SSH client implemented as a Model Context Protocol (MCP) server using the DXT packaging standard.

## Features

### Security Features
- **Encrypted Credential Storage**: Uses OS keychain for secure password storage
- **Host Key Verification**: Validates SSH host keys against known hosts
- **Session Management**: Automatic session timeout and cleanup
- **Audit Logging**: Comprehensive logging of all SSH operations
- **Input Validation**: Strict validation of all user inputs
- **Command Filtering**: Blocks potentially dangerous commands
- **Connection Limits**: Enforces maximum concurrent session limits

### Authentication Methods

1. **SSH Key Authentication** (Recommended ✅)
   - Most secure method
   - Configure via "Default SSH Private Key" in settings
   - Supports passphrase-protected keys

2. **Password Authentication** (Less Secure ⚠️)
   - Available for environments where keys cannot be used
   - Can set a default password in settings (marked with warning)
   - Passwords are stored securely using OS keychain
   - **WARNING**: SSH keys are always more secure than passwords

### Functionality
- SSH connection management with password and key-based authentication
- Command execution with timeout protection
- SFTP file upload/download
- Port forwarding (local)
- Session listing and management
- Host key fingerprint verification

## Installation

1. Install dependencies:
```bash
cd ssh-client-dxt
npm install
```

2. Build the DXT package:
```bash
npm run build
```

3. Install the `.dxt` file in Claude Desktop or compatible MCP client

## Configuration

The extension supports the following configuration options in Claude Desktop:

- `max_sessions`: Maximum concurrent SSH sessions (default: 5)
- `session_timeout`: Session timeout in minutes (default: 30)
- `enable_audit_log`: Enable audit logging (default: true)
- `allowed_hosts_pattern`: Regex pattern for allowed hosts (default: ".*")
- `require_host_verification`: Require host key verification (default: true)
- `enable_mfa`: Enable multi-factor authentication support (default: false)

## Security Guidelines

### Best Practices

1. **Authentication**
   - Use key-based authentication when possible
   - Store passwords securely using the built-in credential storage
   - Never hardcode credentials in scripts

2. **Host Verification**
   - Always verify host keys on first connection
   - Regularly review known hosts
   - Be cautious of host key changes

3. **Session Management**
   - Disconnect sessions when not in use
   - Monitor active sessions regularly
   - Review audit logs for suspicious activity

4. **Command Execution**
   - Be cautious with commands that modify system state
   - Avoid running commands with elevated privileges unless necessary
   - The server blocks certain dangerous patterns automatically

### Audit Logs

Audit logs are stored in `~/.ssh-mcp-audit.log` and include:
- Connection attempts (successful and failed)
- Commands executed
- File transfers
- Port forwarding requests
- Session terminations

Review logs regularly for security monitoring.

### Restricted Operations

The following operations are restricted for security:
- Commands containing `rm -rf /`
- Fork bombs
- Command substitution patterns that could be malicious

## Usage Examples

### Connect to SSH Server
```javascript
{
  "tool": "ssh_connect",
  "params": {
    "host": "example.com",
    "username": "user",
    "password": "password",
    "storeCredentials": true
  }
}
```

### Execute Command
```javascript
{
  "tool": "ssh_execute",
  "params": {
    "sessionId": "session-uuid",
    "command": "ls -la",
    "timeout": 30
  }
}
```

### Upload File
```javascript
{
  "tool": "ssh_upload_file",
  "params": {
    "sessionId": "session-uuid",
    "localPath": "/local/file.txt",
    "remotePath": "/remote/file.txt"
  }
}
```

### Verify Host
```javascript
{
  "tool": "ssh_verify_host",
  "params": {
    "host": "example.com",
    "port": 22
  }
}
```

## Troubleshooting

### Connection Issues
- Verify host and port are correct
- Check firewall settings
- Ensure SSH service is running on target host
- Review audit logs for detailed error messages

### Authentication Failures
- Verify credentials are correct
- Check if key-based auth is required
- Ensure user has SSH access permissions
- Check for account lockouts

### Session Timeouts
- Increase session_timeout in configuration
- Execute commands periodically to maintain activity
- Check network stability

## Security Reporting

If you discover a security vulnerability, please report it to:
- Create a private security advisory on GitHub
- Do not disclose publicly until patched

## License

MIT License - See LICENSE file for details
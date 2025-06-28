# SSH MCP Secure Credential Storage (Encrypted)

The new `ssh-creds` tool provides **encrypted, cross-platform** credential storage for the SSH Client MCP server. Credentials are encrypted with AES-256-GCM and stored outside of Claude's context, ensuring the AI never sees your actual passwords or private keys.

## Key Features

- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Strong Encryption**: AES-256-GCM with Argon2 key derivation
- **Master Password**: All credentials protected by a single master password
- **Secure Permissions**: Platform-specific file permissions (Unix chmod 600, Windows ACLs)
- **Backward Compatible**: Still supports legacy unencrypted credentials

## Installation

### From Source
```bash
cd /Users/slewis/Documents/ssh-client-dxt
cargo build --bin ssh-creds --release
# Binary will be at: target/release/ssh-creds
```

### Create Alias (Optional)
```bash
# macOS/Linux
alias ssh-creds="/Users/slewis/Documents/ssh-client-dxt/target/release/ssh-creds"

# Windows (PowerShell)
Set-Alias ssh-creds "C:\path\to\ssh-client-dxt\target\release\ssh-creds.exe"
```

## Usage

### Store a Password (Encrypted)
```bash
ssh-creds store
# Enter master password for encryption
# Select option 1 (Password)
# Enter username and password
# You'll receive a reference ID like: ref_abc123def456...
```

### Store a Private Key Path (Encrypted)
```bash
ssh-creds store
# Enter master password for encryption
# Select option 2 (Private Key Path)
# Enter username and path to your key file
# You'll receive a reference ID
```

### List Stored Credentials
```bash
ssh-creds list
# Shows all credentials with their status (Encrypted ✓)
```

### Delete a Credential
```bash
ssh-creds delete
# Enter the reference ID to delete
```

## Using with Claude

Once you have a reference ID from `ssh-creds`, use it in Claude exactly as before:

```
Use ssh_connect with:
- host: "192.168.50.189"
- credentialRef: "ref_abc123def456..."
```

When Claude tries to use an encrypted credential, you'll be prompted for your master password in the terminal where the MCP server is running.

## Security Features

1. **Zero Exposure**: Claude never sees your actual credentials or master password
2. **Strong Encryption**: AES-256-GCM encryption with Argon2 key derivation
3. **Local Storage**: Encrypted credentials stored in `~/.ssh-mcp/credentials/`
4. **Platform Security**:
   - **Unix/macOS**: Files have 600 permissions (owner read/write only)
   - **Windows**: ACLs restrict access to current user only
5. **No Network**: Everything stays on your local machine

## Platform-Specific Notes

### Windows
- Native Windows support (no WSL required)
- Uses Windows ACLs to protect credential files
- Works in CMD, PowerShell, and Git Bash

### macOS/Linux
- Uses standard Unix file permissions (chmod 600/700)
- Works in any terminal

## Important Security Notes

- **Master Password**: Choose a strong master password - it protects all your credentials
- **Never share** your master password or credential files
- **Backup**: Consider backing up `~/.ssh-mcp/credentials/` (the files are encrypted)
- The tool runs completely outside of Claude's context
- Reference IDs are safe to share with Claude (they're meaningless without the master password)

## Migration from Old ssh-creds

The new tool is backward compatible. If you have existing unencrypted credentials:
1. They will still work (but remain unencrypted)
2. Consider re-storing them with encryption for better security
3. Use `ssh-creds delete` to remove old unencrypted versions

## Troubleshooting

### "Wrong password" error
- Make sure you're using the correct master password
- Passwords are case-sensitive

### Windows permission errors
- Run as administrator if you see ACL errors
- The tool will still work but with default NTFS permissions

### Can't find ssh-creds
- Make sure you've built it with `cargo build --bin ssh-creds --release`
- Check the binary is in `target/release/ssh-creds` (or `.exe` on Windows)
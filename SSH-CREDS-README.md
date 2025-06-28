# SSH MCP Secure Credential Storage

The `ssh-creds` tool provides **truly secure** credential storage for the SSH Client MCP server. Credentials are stored outside of Claude's context, ensuring the AI never sees your actual passwords or private keys.

## Installation

The tool is located at:
```bash
/Users/slewis/Documents/ssh-client-dxt/ssh-creds
```

You can create an alias for easier access:
```bash
alias ssh-creds="/Users/slewis/Documents/ssh-client-dxt/ssh-creds"
```

## Usage

### Store a Password
```bash
ssh-creds store
# Select option 1 (Password)
# Enter username and password
# You'll receive a reference ID like: ref_abc123def456...
```

### Store a Private Key Path
```bash
ssh-creds store
# Select option 2 (Private Key Path)
# Enter username and path to your key file
# You'll receive a reference ID
```

### List Stored Credentials
```bash
ssh-creds list
```

### Delete a Credential
```bash
ssh-creds delete
# Enter the reference ID to delete
```

## Using with Claude

Once you have a reference ID from `ssh-creds`, use it in Claude like this:

```
Use ssh_connect with:
- host: "192.168.50.189"
- credentialRef: "ref_abc123def456..."
```

That's it! The username and credential are pulled from the secure storage automatically.

## Security Features

1. **Zero Exposure**: Claude never sees your actual credentials
2. **Local Storage**: Credentials stored in `~/.ssh-mcp/credentials/` with 600 permissions
3. **OS Agnostic**: Works on macOS, Linux, and WSL
4. **No Network**: Everything stays on your local machine

## Important Notes

- Never share credentials in the Claude chat
- Always use `ssh-creds store` in your terminal
- The tool runs completely outside of Claude's context
- Reference IDs are safe to share with Claude
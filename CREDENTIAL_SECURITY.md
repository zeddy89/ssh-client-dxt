# Credential Security in SSH Client MCP

This SSH Client MCP server implements a secure credential isolation system that ensures Claude never sees your passwords, private keys, or passphrases.

## How It Works

### 1. Credential Storage
Instead of passing credentials directly through the MCP protocol, the system uses a reference-based approach:

1. **Store credentials securely**: Use the `ssh_credential_store` tool to store credentials
2. **Get a reference ID**: The system returns a UUID reference, not the actual credential
3. **Use the reference**: Pass the reference ID to `ssh_connect` instead of the actual password

### 2. Credential Prompting
When storing credentials:
- The MCP server prompts for input directly in the terminal
- Passwords are hidden using secure input methods
- Claude only sees the reference ID, never the actual credential

### 3. Example Workflow

```json
// Step 1: Store a password (prompted in terminal, not visible to Claude)
{
  "tool": "ssh_credential_store",
  "arguments": {
    "action": "store",
    "credentialType": "password",
    "description": "Production server password"
  }
}
// Returns: { "referenceId": "550e8400-e29b-41d4-a716-446655440000", ... }

// Step 2: Use the reference to connect
{
  "tool": "ssh_connect",
  "arguments": {
    "host": "server.example.com",
    "username": "admin",
    "passwordRef": "550e8400-e29b-41d4-a716-446655440000"  // <- Reference, not password
  }
}
```

### 4. Supported Credential Types
- **Passwords**: For password authentication
- **Private Keys**: For key-based authentication (stores content or path)
- **Passphrases**: For encrypted private keys

### 5. Benefits
- **Zero credential exposure**: Claude never sees actual credentials
- **Session persistence**: Credentials remain available across the session
- **Easy management**: List and remove stored credentials by reference
- **Type safety**: System validates credential types match their usage

### 6. Security Considerations
- Credentials are stored in memory only (not persisted to disk)
- Each credential gets a unique UUID reference
- References cannot be reversed to obtain credentials
- Credentials are cleared when the MCP server stops

This design ensures that even if conversation logs are saved or shared, they will never contain actual credentials - only meaningless reference IDs.
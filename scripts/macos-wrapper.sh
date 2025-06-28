#!/bin/bash
# Wrapper for SSH Client MCP with Claude Desktop
# This script sets up the environment for encrypted credentials

# Optional: Set master password via environment variable
# Uncomment and set your master password here:
# export SSH_MCP_MASTER_PASSWORD="your-master-password-here"

# Alternative: Use macOS Keychain (more secure)
# To store password in keychain, run this once in terminal:
# security add-generic-password -a "ssh-mcp" -s "master-password" -w "your-master-password"

# Log startup
echo "[$(date)] Starting SSH Client MCP with encryption support" >> /tmp/ssh-client-debug.log

# Check if we have a master password source
if [ -n "$SSH_MCP_MASTER_PASSWORD" ]; then
    echo "[$(date)] Using master password from environment variable" >> /tmp/ssh-client-debug.log
elif security find-generic-password -a "ssh-mcp" -s "master-password" -w 2>/dev/null >/dev/null; then
    echo "[$(date)] Master password available in macOS Keychain" >> /tmp/ssh-client-debug.log
else
    echo "[$(date)] WARNING: No master password configured. Encrypted credentials will fail!" >> /tmp/ssh-client-debug.log
    echo "[$(date)] Set SSH_MCP_MASTER_PASSWORD env var or add to keychain with:" >> /tmp/ssh-client-debug.log
    echo "[$(date)]   security add-generic-password -a 'ssh-mcp' -s 'master-password' -w 'your-password'" >> /tmp/ssh-client-debug.log
fi

# Run the actual server
exec /Users/slewis/Documents/ssh-client-dxt/target/release/ssh-client-mcp 2>> /tmp/ssh-client-debug.log
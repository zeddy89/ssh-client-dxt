#!/bin/bash
# Linux wrapper for SSH Client MCP with Claude Desktop
# This script sets up the environment for encrypted credentials

# Optional: Set master password via environment variable
# Uncomment and set your master password here:
# export SSH_MCP_MASTER_PASSWORD="your-master-password-here"

# Alternative: Use Secret Service (GNOME Keyring / KWallet)
# To store password in Secret Service, use ssh-creds-gui or:
# secret-tool store --label="SSH MCP Master Password" service ssh-mcp username master-password

# Log file location
LOG_FILE="/tmp/ssh-client-debug.log"

# Log startup
echo "[$(date)] Starting SSH Client MCP with encryption support" >> "$LOG_FILE"

# Check if we have a master password source
if [ -n "$SSH_MCP_MASTER_PASSWORD" ]; then
    echo "[$(date)] Using master password from environment variable" >> "$LOG_FILE"
else
    # Check Secret Service
    if command -v secret-tool &> /dev/null; then
        if secret-tool lookup service ssh-mcp username master-password &> /dev/null; then
            echo "[$(date)] Master password available in Secret Service" >> "$LOG_FILE"
        else
            echo "[$(date)] WARNING: No master password in Secret Service" >> "$LOG_FILE"
        fi
    else
        echo "[$(date)] WARNING: No master password configured. Encrypted credentials will fail!" >> "$LOG_FILE"
        echo "[$(date)] Install libsecret-tools and run:" >> "$LOG_FILE"
        echo "[$(date)]   secret-tool store --label='SSH MCP Master Password' service ssh-mcp username master-password" >> "$LOG_FILE"
    fi
fi

# Find the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run the actual server
exec "$SCRIPT_DIR/target/release/ssh-client-mcp" 2>> "$LOG_FILE"
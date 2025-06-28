# Windows PowerShell wrapper for SSH Client MCP with Claude Desktop
# This script sets up the environment for encrypted credentials

# Optional: Set master password via environment variable
# Uncomment and set your master password here:
# $env:SSH_MCP_MASTER_PASSWORD = "your-master-password-here"

# Alternative: Use Windows Credential Manager (more secure)
# To store password in Credential Manager, run this once in PowerShell as admin:
# cmdkey /add:ssh-mcp /user:master-password /pass:your-password

# Log file location
$logFile = "$env:TEMP\ssh-client-debug.log"

# Log startup
Add-Content -Path $logFile -Value "[$(Get-Date)] Starting SSH Client MCP with encryption support"

# Check if we have a master password source
if ($env:SSH_MCP_MASTER_PASSWORD) {
    Add-Content -Path $logFile -Value "[$(Get-Date)] Using master password from environment variable"
}
else {
    # Check Windows Credential Manager
    try {
        $cred = cmdkey /list | Select-String "ssh-mcp"
        if ($cred) {
            Add-Content -Path $logFile -Value "[$(Get-Date)] Master password available in Windows Credential Manager"
        }
        else {
            Add-Content -Path $logFile -Value "[$(Get-Date)] WARNING: No master password configured. Encrypted credentials will fail!"
            Add-Content -Path $logFile -Value "[$(Get-Date)] Set SSH_MCP_MASTER_PASSWORD env var or add to Credential Manager with:"
            Add-Content -Path $logFile -Value "[$(Get-Date)]   cmdkey /add:ssh-mcp /user:master-password /pass:your-password"
        }
    }
    catch {
        Add-Content -Path $logFile -Value "[$(Get-Date)] Could not check Credential Manager"
    }
}

# Run the actual server
$exePath = Join-Path $PSScriptRoot "target\release\ssh-client-mcp.exe"
& $exePath 2>> $logFile
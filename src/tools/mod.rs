mod ssh_tools;

pub use ssh_tools::*;

use serde_json::{json, Value};

pub fn get_tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "ssh_connect",
            "description": "Connect to a remote SSH server",
            "inputSchema": {
                "type": "object",
                "required": ["host", "port", "username"],
                "properties": {
                    "host": { "type": "string", "description": "SSH server hostname or IP" },
                    "port": { "type": "integer", "description": "SSH server port", "default": 22 },
                    "username": { "type": "string", "description": "SSH username" },
                    "password": { "type": "string", "description": "SSH password (optional - avoid using directly)" },
                    "passwordRef": { "type": "string", "description": "Reference ID for stored password (preferred)" },
                    "privateKeyPath": { "type": "string", "description": "Path to private key file" },
                    "privateKeyRef": { "type": "string", "description": "Reference ID for stored private key" },
                    "passphrase": { "type": "string", "description": "Private key passphrase (avoid using directly)" },
                    "passphraseRef": { "type": "string", "description": "Reference ID for stored passphrase (preferred)" },
                    "strictHostChecking": { "type": "boolean", "description": "Enable strict host checking", "default": true }
                }
            }
        }),
        json!({
            "name": "ssh_execute",
            "description": "Execute a command on a remote SSH server",
            "inputSchema": {
                "type": "object",
                "required": ["sessionId", "command"],
                "properties": {
                    "sessionId": { "type": "string", "description": "SSH session ID" },
                    "command": { "type": "string", "description": "Command to execute" }
                }
            }
        }),
        json!({
            "name": "ssh_disconnect",
            "description": "Disconnect an SSH session",
            "inputSchema": {
                "type": "object",
                "required": ["sessionId"],
                "properties": {
                    "sessionId": { "type": "string", "description": "SSH session ID to disconnect" }
                }
            }
        }),
        json!({
            "name": "ssh_list_sessions",
            "description": "List all active SSH sessions",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "ssh_upload_file",
            "description": "Upload a file to remote server via SFTP",
            "inputSchema": {
                "type": "object",
                "required": ["sessionId", "localPath", "remotePath"],
                "properties": {
                    "sessionId": { "type": "string", "description": "SSH session ID" },
                    "localPath": { "type": "string", "description": "Local file path" },
                    "remotePath": { "type": "string", "description": "Remote file path" }
                }
            }
        }),
        json!({
            "name": "ssh_download_file",
            "description": "Download a file from remote server via SFTP",
            "inputSchema": {
                "type": "object",
                "required": ["sessionId", "remotePath", "localPath"],
                "properties": {
                    "sessionId": { "type": "string", "description": "SSH session ID" },
                    "remotePath": { "type": "string", "description": "Remote file path" },
                    "localPath": { "type": "string", "description": "Local file path" }
                }
            }
        }),
        json!({
            "name": "ssh_port_forward",
            "description": "Set up SSH port forwarding",
            "inputSchema": {
                "type": "object",
                "required": ["sessionId", "localPort", "remoteHost", "remotePort"],
                "properties": {
                    "sessionId": { "type": "string", "description": "SSH session ID" },
                    "localPort": { "type": "integer", "description": "Local port" },
                    "remoteHost": { "type": "string", "description": "Remote host" },
                    "remotePort": { "type": "integer", "description": "Remote port" },
                    "type": { "type": "string", "enum": ["local", "remote"], "description": "Forward type", "default": "local" }
                }
            }
        }),
        json!({
            "name": "ssh_manage_keys",
            "description": "Manage SSH credentials in system keychain",
            "inputSchema": {
                "type": "object",
                "required": ["action", "service"],
                "properties": {
                    "action": { "type": "string", "enum": ["store", "retrieve", "delete"], "description": "Action to perform" },
                    "service": { "type": "string", "description": "Service identifier" },
                    "account": { "type": "string", "description": "Account name" },
                    "password": { "type": "string", "description": "Password or passphrase (for store action)" }
                }
            }
        }),
        json!({
            "name": "ssh_verify_host",
            "description": "Verify SSH host key fingerprint",
            "inputSchema": {
                "type": "object",
                "required": ["host", "fingerprint"],
                "properties": {
                    "host": { "type": "string", "description": "SSH server hostname" },
                    "port": { "type": "integer", "description": "SSH server port", "default": 22 },
                    "fingerprint": { "type": "string", "description": "Expected host key fingerprint" },
                    "action": { "type": "string", "enum": ["verify", "add", "remove"], "description": "Action to perform", "default": "verify" }
                }
            }
        }),
        json!({
            "name": "ssh_config_manage",
            "description": "Manage saved SSH configurations",
            "inputSchema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": { "type": "string", "enum": ["list", "save", "load", "delete"], "description": "Action to perform" },
                    "name": { "type": "string", "description": "Configuration name" },
                    "config": { 
                        "type": "object", 
                        "description": "SSH configuration (for save action)",
                        "properties": {
                            "host": { "type": "string" },
                            "port": { "type": "integer" },
                            "username": { "type": "string" },
                            "privateKeyPath": { "type": "string" },
                            "description": { "type": "string" }
                        }
                    }
                }
            }
        }),
        json!({
            "name": "ssh_credential_store",
            "description": "Store SSH credentials securely (passwords/keys never visible to Claude)",
            "inputSchema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": { "type": "string", "enum": ["store", "list", "remove"], "description": "Action to perform" },
                    "credentialType": { "type": "string", "enum": ["password", "privateKey", "passphrase"], "description": "Type of credential" },
                    "description": { "type": "string", "description": "Human-readable description of the credential" },
                    "referenceId": { "type": "string", "description": "Reference ID for remove action" }
                }
            }
        })
    ]
}
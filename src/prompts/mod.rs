use crate::config::SshConfig;
use crate::error::{Result, SshMcpError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub fn get_prompt_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "ssh_config",
            "description": "Generate SSH configuration for connecting to a server",
            "arguments": [
                {
                    "name": "host",
                    "description": "SSH server hostname or IP address",
                    "required": true
                },
                {
                    "name": "username",
                    "description": "SSH username",
                    "required": true
                },
                {
                    "name": "authMethod",
                    "description": "Authentication method (password or key)",
                    "required": true
                }
            ]
        }),
        json!({
            "name": "ssh_quick_connect",
            "description": "Quick connect to a saved SSH configuration",
            "arguments": [
                {
                    "name": "configName",
                    "description": "Name of saved configuration",
                    "required": false
                }
            ]
        }),
    ]
}

pub async fn get_ssh_config_prompt(args: Value) -> Result<Value> {
    let host = args
        .get("host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SshMcpError::Validation("Host is required".to_string()))?;

    let username = args
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SshMcpError::Validation("Username is required".to_string()))?;

    let auth_method = args
        .get("authMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SshMcpError::Validation("Auth method is required".to_string()))?;

    let prompt_text = match auth_method {
        "password" => {
            format!(
                "SSH Configuration for {}@{}\n\n\
                Authentication: Password-based\n\n\
                To connect:\n\
                1. Use the ssh_connect tool with your password\n\
                2. For security, consider using ssh_manage_keys to store credentials\n\n\
                Example:\n\
                ssh_connect {{\n\
                  \"host\": \"{}\",\n\
                  \"username\": \"{}\",\n\
                  \"password\": \"your-password\"\n\
                }}",
                username, host, host, username
            )
        }
        "key" => {
            format!(
                "SSH Configuration for {}@{}\n\n\
                Authentication: Key-based\n\n\
                To connect:\n\
                1. Ensure your private key file has correct permissions (600)\n\
                2. Use the ssh_connect tool with your key path\n\n\
                Example:\n\
                ssh_connect {{\n\
                  \"host\": \"{}\",\n\
                  \"username\": \"{}\",\n\
                  \"privateKeyPath\": \"~/.ssh/id_rsa\",\n\
                  \"passphrase\": \"key-passphrase-if-any\"\n\
                }}",
                username, host, host, username
            )
        }
        _ => {
            return Err(SshMcpError::Validation(format!(
                "Invalid auth method: {}",
                auth_method
            )))
        }
    };

    Ok(json!({
        "prompt": prompt_text,
        "metadata": {
            "host": host,
            "username": username,
            "authMethod": auth_method
        }
    }))
}

pub async fn get_quick_connect_prompt(
    args: Value,
    saved_configs: Arc<Mutex<HashMap<String, SshConfig>>>,
) -> Result<Value> {
    let configs = saved_configs.lock().await;

    if let Some(config_name) = args.get("configName").and_then(|v| v.as_str()) {
        // Connect to specific config
        if let Some(config) = configs.get(config_name) {
            let prompt_text = format!(
                "Quick Connect to '{}'\n\n\
                Host: {}@{}:{}\n\
                {}\n\n\
                To connect, use:\n\
                ssh_connect {{\n\
                  \"host\": \"{}\",\n\
                  \"username\": \"{}\",\n\
                  \"port\": {}\n\
                }}",
                config_name,
                config.username,
                config.host,
                config.port,
                config.description.as_deref().unwrap_or("No description"),
                config.host,
                config.username,
                config.port
            );

            Ok(json!({
                "prompt": prompt_text,
                "metadata": {
                    "configName": config_name,
                    "config": config
                }
            }))
        } else {
            Err(SshMcpError::Configuration(format!(
                "Configuration '{}' not found",
                config_name
            )))
        }
    } else {
        // List all configs
        let config_list: Vec<String> = configs
            .iter()
            .map(|(name, config)| {
                format!(
                    "- {}: {}@{}:{} {}",
                    name,
                    config.username,
                    config.host,
                    config.port,
                    config
                        .description
                        .as_deref()
                        .map(|d| format!("({})", d))
                        .unwrap_or_default()
                )
            })
            .collect();

        let prompt_text = if config_list.is_empty() {
            "No saved SSH configurations found.\n\n\
            To save a configuration, use:\n\
            ssh_config_manage {\n\
              \"action\": \"save\",\n\
              \"name\": \"my-server\",\n\
              \"config\": { ... }\n\
            }"
            .to_string()
        } else {
            format!(
                "Available SSH Configurations:\n\n{}\n\n\
                To connect to a saved configuration, use this prompt with the configName argument.",
                config_list.join("\n")
            )
        };

        Ok(json!({
            "prompt": prompt_text,
            "metadata": {
                "configCount": configs.len()
            }
        }))
    }
}

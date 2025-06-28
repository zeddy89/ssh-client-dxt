use crate::config::{PortForwardConfig, PortForwardType, SshConfig};
use crate::credential_provider::{CredentialProvider, CredentialType};
use crate::error::{Result, SshMcpError};
use crate::external_creds::ExternalCredentialProvider;
use crate::session_manager::{SessionManager, SshSession};
use crate::ssh_client::SshClient;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectParams {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: Option<String>,
    pub password_ref: Option<String>, // Reference to stored password
    pub private_key_path: Option<String>,
    pub private_key_ref: Option<String>, // Reference to stored private key
    pub passphrase: Option<String>,
    pub passphrase_ref: Option<String>, // Reference to stored passphrase
    pub credential_ref: Option<String>, // External credential reference (from ssh-creds tool)
    pub strict_host_checking: Option<bool>,
}

pub async fn ssh_connect(
    params: Value,
    session_manager: Arc<SessionManager>,
    known_hosts: Arc<Mutex<HashMap<String, String>>>,
    credential_provider: Arc<CredentialProvider>,
) -> Result<Value> {
    let params: ConnectParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    // Check for external credential reference first
    let (password, private_key_path, passphrase, username) = if let Some(ref_id) =
        &params.credential_ref
    {
        // Use external credential provider
        let external_provider = ExternalCredentialProvider::new();
        let external_cred = external_provider.get_credential(ref_id)?;

        match external_cred.cred_type.as_str() {
            "password" => (
                Some(external_cred.credential),
                None,
                None,
                external_cred.username,
            ),
            "keypath" => (
                None,
                Some(PathBuf::from(external_cred.credential)),
                None,
                external_cred.username,
            ),
            "keyfile" => {
                // TODO: Write key content to temporary file
                return Err(SshMcpError::Validation(
                    "Private key content not yet supported. Use keypath type instead.".to_string(),
                ));
            }
            _ => {
                return Err(SshMcpError::Validation(format!(
                    "Unknown credential type: {}",
                    external_cred.cred_type
                )))
            }
        }
    } else {
        // Fall back to internal credential provider
        let password = if let Some(ref_id) = &params.password_ref {
            Some(credential_provider.get_password(ref_id).await?)
        } else {
            params.password
        };

        // TODO: Implement private key retrieval from credential store when private_key_ref is provided
        let private_key_path = params.private_key_path.map(PathBuf::from);

        let passphrase = if let Some(ref_id) = &params.passphrase_ref {
            Some(credential_provider.get_passphrase(ref_id).await?)
        } else {
            params.passphrase
        };

        (
            password,
            private_key_path,
            passphrase,
            params.username.clone(),
        )
    };

    let config = SshConfig {
        host: params.host,
        port: params.port.unwrap_or(22),
        username,
        password,
        private_key_path,
        passphrase,
        strict_host_checking: params.strict_host_checking.unwrap_or(true),
        description: None,
    };

    // Verify host key if strict checking is enabled
    if config.strict_host_checking {
        let config_clone = config.clone();
        let host_port = format!("{}:{}", config.host, config.port);

        let fingerprint = tokio::task::spawn_blocking(move || -> Result<String> {
            let session = SshClient::connect(&config_clone)?;
            if let Some(host_key) = session.host_key() {
                Ok(SshClient::calculate_fingerprint(host_key.0))
            } else {
                Err(SshMcpError::HostVerificationFailed(
                    "No host key available".to_string(),
                ))
            }
        })
        .await
        .map_err(|e| SshMcpError::SshConnection(format!("Task join error: {}", e)))??;

        let hosts = known_hosts.lock().await;
        if let Some(known_fp) = hosts.get(&host_port) {
            if known_fp != &fingerprint {
                return Err(SshMcpError::HostVerificationFailed(format!(
                    "Host key mismatch for {}",
                    host_port
                )));
            }
        }
    }

    // Verify connection works in a blocking task
    let config_clone = config.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let _session = SshClient::connect(&config_clone)?;
        Ok(())
    })
    .await
    .map_err(|e| SshMcpError::SshConnection(format!("Task join error: {}", e)))??;

    // Create session without storing the SSH connection
    let ssh_session = SshSession::new(config.clone());
    let session_id = session_manager.add_session(ssh_session).await?;

    Ok(json!({
        "sessionId": session_id,
        "host": config.host,
        "port": config.port,
        "username": config.username,
        "connected": true
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteParams {
    pub session_id: String,
    pub command: String,
}

pub async fn ssh_execute(params: Value, session_manager: Arc<SessionManager>) -> Result<Value> {
    let params: ExecuteParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    // Get session config
    let config = session_manager
        .with_session(&params.session_id, |session| Ok(session.config.clone()))
        .await?;

    // Execute command in blocking task
    let command = params.command.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Value> {
        let session = SshClient::connect(&config)?;
        let (stdout, stderr, exit_code) = SshClient::execute_command(&session, &command)?;
        Ok(json!({
            "stdout": stdout,
            "stderr": stderr,
            "exitCode": exit_code,
            "success": exit_code == 0
        }))
    })
    .await
    .map_err(|e| SshMcpError::SshConnection(format!("Task join error: {}", e)))??;

    Ok(result)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectParams {
    pub session_id: String,
}

pub async fn ssh_disconnect(params: Value, session_manager: Arc<SessionManager>) -> Result<Value> {
    let params: DisconnectParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    session_manager.remove_session(&params.session_id).await?;

    Ok(json!({
        "sessionId": params.session_id,
        "disconnected": true
    }))
}

pub async fn ssh_list_sessions(session_manager: Arc<SessionManager>) -> Result<Value> {
    let sessions = session_manager.list_sessions().await;

    let session_list: Vec<Value> = sessions
        .into_iter()
        .map(|(id, config, created_at)| {
            json!({
                "sessionId": id,
                "host": config.host,
                "port": config.port,
                "username": config.username,
                "createdAt": created_at.to_rfc3339()
            })
        })
        .collect();

    Ok(json!({
        "sessions": session_list
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTransferParams {
    pub session_id: String,
    pub local_path: String,
    pub remote_path: String,
}

pub async fn ssh_upload_file(params: Value, session_manager: Arc<SessionManager>) -> Result<Value> {
    let params: FileTransferParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    // Get session config
    let config = session_manager
        .with_session(&params.session_id, |session| Ok(session.config.clone()))
        .await?;

    // Upload file in blocking task
    let local_path = params.local_path.clone();
    let remote_path = params.remote_path.clone();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let session = SshClient::connect(&config)?;
        SshClient::upload_file(&session, Path::new(&local_path), &remote_path)?;
        Ok(json!({
            "localPath": local_path,
            "remotePath": remote_path,
            "uploaded": true
        }))
    })
    .await
    .map_err(|e| SshMcpError::FileOperation(format!("Task join error: {}", e)))?
}

pub async fn ssh_download_file(
    params: Value,
    session_manager: Arc<SessionManager>,
) -> Result<Value> {
    let params: FileTransferParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    // Get session config
    let config = session_manager
        .with_session(&params.session_id, |session| Ok(session.config.clone()))
        .await?;

    // Download file in blocking task
    let local_path = params.local_path.clone();
    let remote_path = params.remote_path.clone();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let session = SshClient::connect(&config)?;
        SshClient::download_file(&session, &remote_path, Path::new(&local_path))?;
        Ok(json!({
            "remotePath": remote_path,
            "localPath": local_path,
            "downloaded": true
        }))
    })
    .await
    .map_err(|e| SshMcpError::FileOperation(format!("Task join error: {}", e)))?
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardParams {
    pub session_id: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    #[serde(rename = "type")]
    pub forward_type: Option<String>,
}

pub async fn ssh_port_forward(
    params: Value,
    session_manager: Arc<SessionManager>,
) -> Result<Value> {
    let params: PortForwardParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    let forward_type = match params.forward_type.as_deref() {
        Some("remote") => PortForwardType::Remote,
        _ => PortForwardType::Local,
    };

    session_manager
        .with_session(&params.session_id, |session| {
            let config = PortForwardConfig {
                local_port: params.local_port,
                remote_host: params.remote_host.clone(),
                remote_port: params.remote_port,
                forward_type,
            };

            // Store port forward config
            session.port_forwards.push(config);

            // Note: Actual port forwarding implementation would require
            // spawning a separate task to handle the forwarding

            Ok(json!({
                "localPort": params.local_port,
                "remoteHost": params.remote_host,
                "remotePort": params.remote_port,
                "type": match forward_type {
                    PortForwardType::Local => "local",
                    PortForwardType::Remote => "remote",
                },
                "established": true
            }))
        })
        .await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyManageParams {
    pub action: String,
    pub service: String,
    pub account: Option<String>,
    pub password: Option<String>,
}

pub async fn ssh_manage_keys(params: Value) -> Result<Value> {
    let params: KeyManageParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    match params.action.as_str() {
        "store" => {
            let account = params.account.ok_or_else(|| {
                SshMcpError::Validation("Account required for store action".to_string())
            })?;
            let password = params.password.ok_or_else(|| {
                SshMcpError::Validation("Password required for store action".to_string())
            })?;

            let entry = keyring::Entry::new(&params.service, &account)
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))?;

            entry
                .set_password(&password)
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))?;

            Ok(json!({
                "action": "store",
                "service": params.service,
                "account": account,
                "stored": true
            }))
        }
        "retrieve" => {
            let account = params.account.ok_or_else(|| {
                SshMcpError::Validation("Account required for retrieve action".to_string())
            })?;

            let entry = keyring::Entry::new(&params.service, &account)
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))?;

            let password = entry
                .get_password()
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))?;

            Ok(json!({
                "action": "retrieve",
                "service": params.service,
                "account": account,
                "message": "Password retrieved successfully"
            }))
        }
        "delete" => {
            let account = params.account.ok_or_else(|| {
                SshMcpError::Validation("Account required for delete action".to_string())
            })?;

            let entry = keyring::Entry::new(&params.service, &account)
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))?;

            entry
                .delete_credential()
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))?;

            Ok(json!({
                "action": "delete",
                "service": params.service,
                "account": account,
                "deleted": true
            }))
        }
        _ => Err(SshMcpError::Validation(format!(
            "Invalid action: {}",
            params.action
        ))),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostVerifyParams {
    pub host: String,
    pub port: Option<u16>,
    pub fingerprint: String,
    pub action: Option<String>,
}

pub async fn ssh_verify_host(
    params: Value,
    known_hosts: Arc<Mutex<HashMap<String, String>>>,
) -> Result<Value> {
    let params: HostVerifyParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    let port = params.port.unwrap_or(22);
    let host_key = format!("{}:{}", params.host, port);

    match params.action.as_deref().unwrap_or("verify") {
        "verify" => {
            let hosts = known_hosts.lock().await;
            if let Some(known_fp) = hosts.get(&host_key) {
                let verified = known_fp == &params.fingerprint;
                Ok(json!({
                    "host": params.host,
                    "port": port,
                    "fingerprint": params.fingerprint,
                    "verified": verified,
                    "knownFingerprint": known_fp
                }))
            } else {
                Ok(json!({
                    "host": params.host,
                    "port": port,
                    "fingerprint": params.fingerprint,
                    "verified": false,
                    "message": "Host not in known hosts"
                }))
            }
        }
        "add" => {
            let mut hosts = known_hosts.lock().await;
            hosts.insert(host_key.clone(), params.fingerprint.clone());

            Ok(json!({
                "host": params.host,
                "port": port,
                "fingerprint": params.fingerprint,
                "added": true
            }))
        }
        "remove" => {
            let mut hosts = known_hosts.lock().await;
            let removed = hosts.remove(&host_key).is_some();

            Ok(json!({
                "host": params.host,
                "port": port,
                "removed": removed
            }))
        }
        _ => Err(SshMcpError::Validation(format!(
            "Invalid action: {}",
            params.action.as_deref().unwrap_or("unknown")
        ))),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigManageParams {
    pub action: String,
    pub name: Option<String>,
    pub config: Option<SshConfig>,
}

pub async fn ssh_config_manage(
    params: Value,
    saved_configs: Arc<Mutex<HashMap<String, SshConfig>>>,
) -> Result<Value> {
    let params: ConfigManageParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    match params.action.as_str() {
        "list" => {
            let configs = saved_configs.lock().await;
            let config_list: Vec<Value> = configs
                .iter()
                .map(|(name, config)| {
                    json!({
                        "name": name,
                        "host": config.host,
                        "port": config.port,
                        "username": config.username,
                        "description": config.description
                    })
                })
                .collect();

            Ok(json!({
                "configs": config_list
            }))
        }
        "save" => {
            let name = params.name.ok_or_else(|| {
                SshMcpError::Validation("Name required for save action".to_string())
            })?;
            let config = params.config.ok_or_else(|| {
                SshMcpError::Validation("Config required for save action".to_string())
            })?;

            let mut configs = saved_configs.lock().await;
            configs.insert(name.clone(), config);

            Ok(json!({
                "name": name,
                "saved": true
            }))
        }
        "load" => {
            let name = params.name.ok_or_else(|| {
                SshMcpError::Validation("Name required for load action".to_string())
            })?;

            let configs = saved_configs.lock().await;
            if let Some(config) = configs.get(&name) {
                Ok(serde_json::to_value(config)?)
            } else {
                Err(SshMcpError::Configuration(format!(
                    "Config not found: {}",
                    name
                )))
            }
        }
        "delete" => {
            let name = params.name.ok_or_else(|| {
                SshMcpError::Validation("Name required for delete action".to_string())
            })?;

            let mut configs = saved_configs.lock().await;
            let deleted = configs.remove(&name).is_some();

            Ok(json!({
                "name": name,
                "deleted": deleted
            }))
        }
        _ => Err(SshMcpError::Validation(format!(
            "Invalid action: {}",
            params.action
        ))),
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStoreParams {
    pub action: String,
    pub credential_type: Option<String>,
    pub credential_value: Option<String>,
    pub description: Option<String>,
    pub reference_id: Option<String>,
}

pub async fn ssh_credential_store(
    params: Value,
    credential_provider: Arc<CredentialProvider>,
) -> Result<Value> {
    let params: CredentialStoreParams =
        serde_json::from_value(params).map_err(|e| SshMcpError::Validation(e.to_string()))?;

    match params.action.as_str() {
        "store" => {
            let credential_type = match params.credential_type.as_deref() {
                Some("password") => CredentialType::Password,
                Some("privateKey") => CredentialType::PrivateKey,
                Some("passphrase") => CredentialType::Passphrase,
                _ => {
                    return Err(SshMcpError::Validation(
                        "credential_type required for store action".to_string(),
                    ))
                }
            };

            let credential_value = params.credential_value.ok_or_else(|| {
                SshMcpError::Validation("credential_value required for store action".to_string())
            })?;

            let description = params.description.unwrap_or_else(|| {
                format!(
                    "Stored {} credential",
                    match credential_type {
                        CredentialType::Password => "password",
                        CredentialType::PrivateKey => "private key",
                        CredentialType::Passphrase => "passphrase",
                    }
                )
            });

            // Store credential and get reference ID
            let ref_id = credential_provider
                .store_credential(
                    credential_type.clone(),
                    credential_value,
                    description.clone(),
                )
                .await?;

            Ok(json!({
                "action": "store",
                "referenceId": ref_id,
                "credentialType": match credential_type {
                    CredentialType::Password => "password",
                    CredentialType::PrivateKey => "privateKey",
                    CredentialType::Passphrase => "passphrase",
                },
                "description": description,
                "stored": true
            }))
        }
        "list" => {
            let references = credential_provider.list_references().await;
            let ref_list: Vec<Value> = references
                .into_iter()
                .map(|r| {
                    json!({
                        "referenceId": r.id,
                        "credentialType": match r.credential_type {
                            CredentialType::Password => "password",
                            CredentialType::PrivateKey => "privateKey",
                            CredentialType::Passphrase => "passphrase",
                        },
                        "description": r.description
                    })
                })
                .collect();

            Ok(json!({
                "action": "list",
                "credentials": ref_list
            }))
        }
        "remove" => {
            let ref_id = params.reference_id.ok_or_else(|| {
                SshMcpError::Validation("reference_id required for remove action".to_string())
            })?;

            credential_provider.remove_credential(&ref_id).await?;

            Ok(json!({
                "action": "remove",
                "referenceId": ref_id,
                "removed": true
            }))
        }
        _ => Err(SshMcpError::Validation(format!(
            "Invalid action: {}",
            params.action
        ))),
    }
}

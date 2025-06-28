use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub max_sessions: usize,
    pub session_timeout: Duration,
    pub enable_audit_logging: bool,
    pub audit_log_path: Option<PathBuf>,
    pub known_hosts_path: PathBuf,
    pub saved_configs_path: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let home_dir = directories::UserDirs::new()
            .and_then(|dirs| Some(dirs.home_dir().to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        Self {
            max_sessions: std::env::var("MAX_SESSIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            session_timeout: Duration::from_secs(
                std::env::var("SESSION_TIMEOUT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1800),
            ),
            enable_audit_logging: std::env::var("ENABLE_AUDIT_LOGGING")
                .ok()
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(false),
            audit_log_path: std::env::var("AUDIT_LOG_PATH").ok().map(PathBuf::from),
            known_hosts_path: home_dir.join(".ssh").join("known_hosts"),
            saved_configs_path: home_dir.join(".ssh-mcp").join("configs.json"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub strict_host_checking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardConfig {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub forward_type: PortForwardType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortForwardType {
    Local,
    Remote,
}

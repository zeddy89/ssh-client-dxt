use thiserror::Error;

#[derive(Error, Debug)]
pub enum SshMcpError {
    #[error("SSH connection error: {0}")]
    SshConnection(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Maximum sessions reached: {0}")]
    MaxSessionsReached(usize),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Host verification failed: {0}")]
    HostVerificationFailed(String),

    #[error("File operation failed: {0}")]
    FileOperation(String),

    #[error("Port forwarding failed: {0}")]
    PortForwarding(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Credential storage error: {0}")]
    CredentialStorage(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("MCP protocol error: {0}")]
    McpProtocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SSH2 error: {0}")]
    Ssh2(#[from] ssh2::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

pub type Result<T> = std::result::Result<T, SshMcpError>;
pub type SSHError = SshMcpError;

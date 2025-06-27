pub mod config;
pub mod credential_provider;
pub mod error;
pub mod mcp_server;
pub mod prompts;
pub mod session_manager;
pub mod ssh_client;
pub mod tools;

// Re-export commonly used types
pub use error::{Result, SshMcpError};
pub use mcp_server::McpServer;
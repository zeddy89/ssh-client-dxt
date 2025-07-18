#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::type_complexity)]
#![allow(clippy::bind_instead_of_map)]
#![allow(clippy::new_without_default)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_inception)]

pub mod command_validator;
pub mod config;
pub mod connection_pool;
pub mod credential_provider;
pub mod error;
pub mod external_creds;
pub mod mcp_server;
pub mod prompts;
pub mod session_manager;
pub mod smart_session;
pub mod ssh_client;
pub mod system_detector;
pub mod tools;

#[cfg(test)]
mod tests;

// Re-export commonly used types
pub use error::{Result, SshMcpError};
pub use mcp_server::McpServer;

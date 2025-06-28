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

use anyhow::Result;
use jsonrpc_core::IoHandler;
use jsonrpc_stdio_server::ServerBuilder;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod credential_provider;
mod error;
mod mcp_server;
mod prompts;
mod session_manager;
mod ssh_client;
mod tools;

use crate::mcp_server::McpServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    info!("Starting SSH Client MCP Server");

    // Create MCP server instance
    let mcp_server = Arc::new(Mutex::new(McpServer::new().await?));

    // Set up JSON-RPC handler
    let mut io = IoHandler::new();

    // Register MCP methods
    mcp_server.lock().await.register_methods(&mut io)?;

    // Start stdio server
    let server = ServerBuilder::new(io).build();

    info!("SSH Client MCP Server is running");

    // Run server
    server.await;

    info!("SSH Client MCP Server shutting down");
    Ok(())
}

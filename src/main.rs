use anyhow::Result;
use jsonrpc_core::{IoHandler, Params, Value};
use jsonrpc_stdio_server::ServerBuilder;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod ssh_client;
mod mcp_server;
mod session_manager;
mod config;
mod error;
mod tools;
mod prompts;

use crate::mcp_server::McpServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .json()
        .init();

    info!("Starting SSH Client MCP Server");

    // Create MCP server instance
    let server = Arc::new(Mutex::new(McpServer::new().await?));

    // Set up JSON-RPC handler
    let mut io = IoHandler::new();
    
    // Register MCP methods
    server.lock().await.register_methods(&mut io)?;

    // Start stdio server
    let server_handle = ServerBuilder::new(io)
        .build();

    info!("SSH Client MCP Server is running");

    // Run server
    server_handle.wait();

    info!("SSH Client MCP Server shutting down");
    Ok(())
}
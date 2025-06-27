use anyhow::Result;
use jsonrpc_core::IoHandler;
use jsonrpc_stdio_server::ServerBuilder;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod ssh_client;
mod mcp_server;
mod session_manager;
mod config;
mod error;
mod tools;
mod prompts;
mod credential_provider;

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
    let server = ServerBuilder::new(io)
        .build();

    info!("SSH Client MCP Server is running");

    // Run server
    server.await;

    info!("SSH Client MCP Server shutting down");
    Ok(())
}
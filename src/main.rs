
use anyhow::Result;
use jsonrpc_core::IoHandler;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;
use tracing_subscriber::EnvFilter;

mod config;
mod credential_provider;
mod error;
mod external_creds;
mod mcp_server;
mod prompts;
mod session_manager;
mod ssh_client;
mod tools;

use crate::mcp_server::McpServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging to stderr to avoid interfering with JSON-RPC on stdout
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error")),
        )
        .with_writer(std::io::stderr)
        .init();

    debug!("Starting SSH Client MCP Server");

    // Create MCP server instance
    let mcp_server = Arc::new(Mutex::new(McpServer::new().await?));

    // Set up JSON-RPC handler
    let mut io = IoHandler::new();

    // Register MCP methods
    mcp_server.lock().await.register_methods(&mut io)?;

    // Use a custom stdio implementation that properly handles the MCP protocol
    use std::io::{BufRead, BufReader, Write};
    use tokio::task;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();

    debug!("SSH Client MCP Server is running");

    // Read JSON-RPC messages from stdin
    let reader = BufReader::new(stdin);
    for line in reader.lines() {
        match line {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }

                eprintln!("Received: {}", line);

                // Process the request
                let response = task::block_in_place(|| {
                    let runtime = tokio::runtime::Handle::current();
                    runtime.block_on(async { io.handle_request(&line).await })
                });

                if let Some(response_str) = response {
                    writeln!(stdout_lock, "{}", response_str)?;
                    stdout_lock.flush()?;
                    eprintln!("Sent: {}", response_str);
                }
            }
            Err(e) => {
                eprintln!("Error reading stdin: {}", e);
                break;
            }
        }
    }

    eprintln!("SSH Client MCP Server shutting down - stdin closed");
    Ok(())
}

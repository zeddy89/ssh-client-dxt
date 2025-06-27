use crate::config::{ServerConfig, SshConfig};
use crate::error::{Result, SshMcpError};
use crate::session_manager::{SessionManager, SshSession};
use crate::ssh_client::SshClient;
use crate::tools;
use crate::prompts;
use crate::credential_provider::CredentialProvider;
use jsonrpc_core::{IoHandler, Params, Value};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

pub struct McpServer {
    config: ServerConfig,
    session_manager: Arc<SessionManager>,
    known_hosts: Arc<Mutex<HashMap<String, String>>>,
    saved_configs: Arc<Mutex<HashMap<String, SshConfig>>>,
    audit_logger: Option<Arc<Mutex<AuditLogger>>>,
    credential_provider: Arc<CredentialProvider>,
}

impl McpServer {
    pub async fn new() -> Result<Self> {
        let config = ServerConfig::default();
        
        // Initialize session manager
        let session_manager = Arc::new(SessionManager::new(
            config.max_sessions,
            config.session_timeout,
        ));
        
        // Load known hosts
        let known_hosts = Arc::new(Mutex::new(Self::load_known_hosts(&config.known_hosts_path).await));
        
        // Load saved configurations
        let saved_configs = Arc::new(Mutex::new(Self::load_saved_configs(&config.saved_configs_path).await));
        
        // Initialize audit logger if enabled
        let audit_logger = if config.enable_audit_logging {
            Some(Arc::new(Mutex::new(AuditLogger::new(config.audit_log_path.clone())?)))
        } else {
            None
        };
        
        // Initialize credential provider
        let credential_provider = Arc::new(CredentialProvider::new());
        
        Ok(Self {
            config,
            session_manager,
            known_hosts,
            saved_configs,
            audit_logger,
            credential_provider,
        })
    }
    
    pub fn register_methods(&self, io: &mut IoHandler) -> Result<()> {
        // Initialize method
        let server_info = json!({
            "protocolVersion": "0.1.0",
            "serverName": "ssh-client-mcp",
            "serverVersion": "0.1.0",
            "capabilities": {
                "tools": true,
                "prompts": true
            }
        });
        
        io.add_sync_method("initialize", move |_: Params| {
            Ok(server_info.clone())
        });
        
        // List tools
        io.add_sync_method("tools/list", |_: Params| {
            Ok(json!({
                "tools": tools::get_tool_definitions()
            }))
        });
        
        // List prompts  
        io.add_sync_method("prompts/list", |_: Params| {
            Ok(json!({
                "prompts": prompts::get_prompt_definitions()
            }))
        });
        
        // Tool call handler
        let session_manager = self.session_manager.clone();
        let known_hosts = self.known_hosts.clone();
        let saved_configs = self.saved_configs.clone();
        let audit_logger = self.audit_logger.clone();
        let credential_provider = self.credential_provider.clone();
        
        io.add_method("tools/call", move |params: Params| {
            let session_manager = session_manager.clone();
            let known_hosts = known_hosts.clone();
            let saved_configs = saved_configs.clone();
            let audit_logger = audit_logger.clone();
            let credential_provider = credential_provider.clone();
            
            Box::pin(async move {
                let params: ToolCallParams = params.parse()?;
                
                // Log tool call if audit logging is enabled
                if let Some(logger) = &audit_logger {
                    logger.lock().await.log_tool_call(&params.name, &params.arguments).await;
                }
                
                let result = match params.name.as_str() {
                    "ssh_connect" => {
                        tools::ssh_connect(params.arguments, session_manager.clone(), known_hosts.clone(), credential_provider.clone()).await
                    },
                    "ssh_execute" => {
                        tools::ssh_execute(params.arguments, session_manager.clone()).await
                    },
                    "ssh_disconnect" => {
                        tools::ssh_disconnect(params.arguments, session_manager.clone()).await
                    },
                    "ssh_list_sessions" => {
                        tools::ssh_list_sessions(session_manager.clone()).await
                    },
                    "ssh_upload_file" => {
                        tools::ssh_upload_file(params.arguments, session_manager.clone()).await
                    },
                    "ssh_download_file" => {
                        tools::ssh_download_file(params.arguments, session_manager.clone()).await
                    },
                    "ssh_port_forward" => {
                        tools::ssh_port_forward(params.arguments, session_manager.clone()).await
                    },
                    "ssh_manage_keys" => {
                        tools::ssh_manage_keys(params.arguments).await
                    },
                    "ssh_verify_host" => {
                        tools::ssh_verify_host(params.arguments, known_hosts.clone()).await
                    },
                    "ssh_config_manage" => {
                        tools::ssh_config_manage(params.arguments, saved_configs.clone()).await
                    },
                    "ssh_credential_store" => {
                        tools::ssh_credential_store(params.arguments, credential_provider.clone()).await
                    },
                    _ => Err(SshMcpError::McpProtocol(format!("Unknown tool: {}", params.name))),
                };
                
                match result {
                    Ok(value) => Ok(value),
                    Err(e) => {
                        error!("Tool call failed: {}", e);
                        Ok(json!({
                            "error": e.to_string()
                        }))
                    }
                }
            })
        });
        
        // Prompt get handler
        let saved_configs = self.saved_configs.clone();
        
        io.add_method("prompts/get", move |params: Params| {
            let saved_configs = saved_configs.clone();
            
            Box::pin(async move {
                let params: PromptGetParams = params.parse()?;
                
                match params.name.as_str() {
                    "ssh_config" => {
                        prompts::get_ssh_config_prompt(params.arguments).await
                    },
                    "ssh_quick_connect" => {
                        prompts::get_quick_connect_prompt(params.arguments, saved_configs.clone()).await
                    },
                    _ => Err(SshMcpError::McpProtocol(format!("Unknown prompt: {}", params.name))),
                }.map_err(|e| {
                    error!("Prompt get failed: {}", e);
                    jsonrpc_core::Error::internal_error()
                })
            })
        });
        
        Ok(())
    }
    
    async fn load_known_hosts(path: &PathBuf) -> HashMap<String, String> {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                let mut hosts = HashMap::new();
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        hosts.insert(parts[0].to_string(), parts[2].to_string());
                    }
                }
                hosts
            }
            Err(_) => HashMap::new(),
        }
    }
    
    async fn load_saved_configs(path: &PathBuf) -> HashMap<String, SshConfig> {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                serde_json::from_str(&content).unwrap_or_default()
            }
            Err(_) => HashMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ToolCallParams {
    name: String,
    arguments: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct PromptGetParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

pub struct AuditLogger {
    log_path: Option<PathBuf>,
}

impl AuditLogger {
    pub fn new(log_path: Option<PathBuf>) -> Result<Self> {
        Ok(Self { log_path })
    }
    
    pub async fn log_tool_call(&self, tool_name: &str, arguments: &Value) {
        let log_entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "tool": tool_name,
            "arguments": arguments,
        });
        
        if let Some(path) = &self.log_path {
            let log_line = format!("{}\n", serde_json::to_string(&log_entry).unwrap());
            if let Err(e) = tokio::fs::write(path, log_line).await {
                error!("Failed to write audit log: {}", e);
            }
        }
    }
}
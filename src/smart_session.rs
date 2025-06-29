use serde::{Deserialize, Serialize};
use std::io::Read;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::command_validator::{CommandHistory, CommandValidation, CommandValidator};
use crate::error::SSHError;
use crate::session_manager::SshSession as ManagedSession;
use crate::ssh_client::SshClient;
use crate::system_detector::{OsType, SystemDetector, SystemInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartSession {
    pub session_id: String,
    pub system_info: SystemInfo,
    pub safe_mode: bool,
    pub auto_sudo: bool,
    pub correct_commands: bool,
    pub command_stats: CommandStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandStats {
    pub total_commands: usize,
    pub corrected_commands: usize,
    pub blocked_commands: usize,
    pub failed_commands: usize,
    pub successful_commands: usize,
}

pub struct SmartSessionManager {
    sessions: Arc<RwLock<std::collections::HashMap<String, SmartSessionWrapper>>>,
}

struct SmartSessionWrapper {
    session: ManagedSession,
    smart_session: SmartSession,
    validator: CommandValidator,
    history: CommandHistory,
}

impl SmartSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn create_smart_session(
        &self,
        session: ManagedSession,
        safe_mode: bool,
        auto_sudo: bool,
        correct_commands: bool,
    ) -> Result<SmartSession, SSHError> {
        let session_id = session.id.clone();
        let config = session.config.clone();

        // Detect system information in a blocking task
        let system_info = tokio::task::spawn_blocking(move || -> Result<SystemInfo, SSHError> {
            let ssh_session = SshClient::connect(&config)?;
            SystemDetector::detect(&ssh_session)
        })
        .await
        .map_err(|e| SSHError::Connection(format!("Task join error: {}", e)))??;

        let smart_session = SmartSession {
            session_id: session_id.clone(),
            system_info: system_info.clone(),
            safe_mode,
            auto_sudo,
            correct_commands,
            command_stats: CommandStats::default(),
        };

        let validator = CommandValidator::new(system_info);
        let history = CommandHistory::new(100);

        let wrapper = SmartSessionWrapper {
            session,
            smart_session: smart_session.clone(),
            validator,
            history,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, wrapper);

        Ok(smart_session)
    }

    pub async fn execute_smart_command(
        &self,
        session_id: &str,
        command: &str,
        timeout_ms: Option<u64>,
    ) -> Result<SmartCommandResult, SSHError> {
        let mut sessions = self.sessions.write().await;
        let wrapper = sessions
            .get_mut(session_id)
            .ok_or_else(|| SSHError::NotFound("Session not found".to_string()))?;

        // Update statistics
        wrapper.smart_session.command_stats.total_commands += 1;

        // Validate command
        let validation = wrapper.validator.validate_command(command);
        let (final_command, was_modified) = match validation {
            CommandValidation::Valid => {
                let cmd = if wrapper.smart_session.auto_sudo {
                    wrapper.validator.add_sudo_if_needed(command)
                } else {
                    command.to_string()
                };
                (cmd, false)
            }
            CommandValidation::Corrected(corrected) => {
                wrapper.smart_session.command_stats.corrected_commands += 1;
                if wrapper.smart_session.correct_commands {
                    let cmd = if wrapper.smart_session.auto_sudo {
                        wrapper.validator.add_sudo_if_needed(&corrected)
                    } else {
                        corrected.clone()
                    };
                    (cmd, true)
                } else {
                    return Ok(SmartCommandResult {
                        output: String::new(),
                        exit_code: None,
                        original_command: command.to_string(),
                        executed_command: None,
                        suggestion: Some(format!("Did you mean: {}", corrected)),
                        was_corrected: false,
                        was_blocked: false,
                        system_info: Some(wrapper.smart_session.system_info.clone()),
                    });
                }
            }
            CommandValidation::Alternative(alternative) => {
                wrapper.smart_session.command_stats.corrected_commands += 1;
                if wrapper.smart_session.correct_commands {
                    (alternative.clone(), true)
                } else {
                    return Ok(SmartCommandResult {
                        output: String::new(),
                        exit_code: None,
                        original_command: command.to_string(),
                        executed_command: None,
                        suggestion: Some(format!("Try using: {}", alternative)),
                        was_corrected: false,
                        was_blocked: false,
                        system_info: Some(wrapper.smart_session.system_info.clone()),
                    });
                }
            }
            CommandValidation::Dangerous(dangerous) => {
                wrapper.smart_session.command_stats.blocked_commands += 1;
                if wrapper.smart_session.safe_mode {
                    return Ok(SmartCommandResult {
                        output: format!("Command blocked for safety: {}", dangerous),
                        exit_code: None,
                        original_command: command.to_string(),
                        executed_command: None,
                        suggestion: Some(
                            "This command could be dangerous. Disable safe mode to execute."
                                .to_string(),
                        ),
                        was_corrected: false,
                        was_blocked: true,
                        system_info: Some(wrapper.smart_session.system_info.clone()),
                    });
                } else {
                    (command.to_string(), false)
                }
            }
        };

        // Execute the command in a blocking task
        let config = wrapper.session.config.clone();
        let final_command_clone = final_command.clone();
        let (output_str, stderr_str, exit_status) = tokio::task::spawn_blocking(
            move || -> Result<(String, String, Option<u32>), SSHError> {
                let ssh_session = SshClient::connect(&config)?;

                let mut channel = ssh_session.channel_session().map_err(|e| {
                    SSHError::Connection(format!("Failed to create channel: {}", e))
                })?;

                channel.exec(&final_command_clone).map_err(|e| {
                    SSHError::Connection(format!("Failed to execute command: {}", e))
                })?;

                let mut output = String::new();
                channel
                    .read_to_string(&mut output)
                    .map_err(|e| SSHError::Connection(format!("Failed to read output: {}", e)))?;

                let mut stderr = String::new();
                channel
                    .stderr()
                    .read_to_string(&mut stderr)
                    .map_err(|e| SSHError::Connection(format!("Failed to read stderr: {}", e)))?;

                channel
                    .wait_close()
                    .map_err(|e| SSHError::Connection(format!("Failed to close channel: {}", e)))?;

                let exit_status = channel.exit_status().map_err(|e| {
                    SSHError::Connection(format!("Failed to get exit status: {}", e))
                })?;

                Ok((output, stderr, Some(exit_status as u32)))
            },
        )
        .await
        .map_err(|e| SSHError::Connection(format!("Task join error: {}", e)))??;

        let exit_code = exit_status;

        // Update statistics based on exit code
        match exit_code {
            Some(0) => wrapper.smart_session.command_stats.successful_commands += 1,
            Some(_) => wrapper.smart_session.command_stats.failed_commands += 1,
            None => {}
        }

        // Add to history
        wrapper.history.add(
            command.to_string(),
            if was_modified {
                Some(final_command.clone())
            } else {
                None
            },
            exit_code.map(|c| c as i32),
        );

        let combined_output = if stderr_str.is_empty() {
            output_str
        } else {
            format!("{}\nSTDERR:\n{}", output_str, stderr_str)
        };

        Ok(SmartCommandResult {
            output: combined_output,
            exit_code,
            original_command: command.to_string(),
            executed_command: Some(final_command),
            suggestion: None,
            was_corrected: was_modified,
            was_blocked: false,
            system_info: Some(wrapper.smart_session.system_info.clone()),
        })
    }

    pub async fn get_session_info(&self, session_id: &str) -> Result<SmartSession, SSHError> {
        let sessions = self.sessions.read().await;
        let wrapper = sessions
            .get(session_id)
            .ok_or_else(|| SSHError::NotFound("Session not found".to_string()))?;
        Ok(wrapper.smart_session.clone())
    }

    pub async fn get_command_suggestions(
        &self,
        session_id: &str,
        partial_command: &str,
    ) -> Result<Vec<String>, SSHError> {
        let sessions = self.sessions.read().await;
        let wrapper = sessions
            .get(session_id)
            .ok_or_else(|| SSHError::NotFound("Session not found".to_string()))?;

        let mut suggestions = Vec::new();

        // Add system-specific command suggestions based on the detected OS
        match &wrapper.smart_session.system_info.os_type {
            OsType::Linux(_) => {
                suggestions.extend(
                    vec![
                        "systemctl status",
                        "journalctl -xe",
                        "df -h",
                        "free -m",
                        "netstat -tuln",
                        "ss -tuln",
                        "ip addr show",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
            }
            OsType::MacOS => {
                suggestions.extend(
                    vec![
                        "brew list",
                        "diskutil list",
                        "top -l 1",
                        "netstat -an",
                        "ifconfig",
                        "system_profiler",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
            }
            _ => {}
        }

        // Filter based on partial command
        suggestions.retain(|s| s.starts_with(partial_command));

        Ok(suggestions)
    }

    pub async fn remove_session(&self, session_id: &str) -> Result<(), SSHError> {
        let mut sessions = self.sessions.write().await;
        sessions
            .remove(session_id)
            .ok_or_else(|| SSHError::NotFound("Session not found".to_string()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartCommandResult {
    pub output: String,
    pub exit_code: Option<u32>,
    pub original_command: String,
    pub executed_command: Option<String>,
    pub suggestion: Option<String>,
    pub was_corrected: bool,
    pub was_blocked: bool,
    pub system_info: Option<SystemInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smart_session_creation() {
        // This would require a mock SSH connection for proper testing
        // For now, we'll just test the structure
        let manager = SmartSessionManager::new();
        assert!(manager.sessions.read().await.is_empty());
    }
}

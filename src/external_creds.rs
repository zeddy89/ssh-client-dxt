use crate::error::{Result, SshMcpError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub username: String,
    pub credential: String,
    pub description: String,
    pub created: String,
}

pub struct ExternalCredentialProvider {
    creds_dir: PathBuf,
}

impl ExternalCredentialProvider {
    pub fn new() -> Self {
        let mut creds_dir = dirs::home_dir().unwrap_or_default();
        creds_dir.push(".ssh-mcp");
        creds_dir.push("credentials");

        Self { creds_dir }
    }

    pub fn get_credential(&self, ref_id: &str) -> Result<ExternalCredential> {
        let cred_file = self.creds_dir.join(format!("{}.json", ref_id));

        if !cred_file.exists() {
            return Err(SshMcpError::CredentialStorage(format!(
                "Credential not found: {}. Use 'ssh-creds store' to create it.",
                ref_id
            )));
        }

        // Check if this is an encrypted credential
        let content = fs::read_to_string(&cred_file).map_err(|e| {
            SshMcpError::CredentialStorage(format!("Failed to read credential: {}", e))
        })?;

        // Try to parse as encrypted credential first
        if content.contains("\"encrypted_credential\"") {
            // This is an encrypted credential, we need to decrypt it
            use std::process::Command;
            
            // Find the ssh-creds binary
            let ssh_creds_path = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("ssh-creds")))
                .unwrap_or_else(|| PathBuf::from("ssh-creds"));
            
            // ssh-creds will get the password from env/keychain/stdin itself
            let output = Command::new(&ssh_creds_path)
                .arg("export")
                .arg(ref_id)
                .output()
                .map_err(|e| {
                    SshMcpError::CredentialStorage(format!("Failed to run ssh-creds: {}", e))
                })?;
            
            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                return Err(SshMcpError::CredentialStorage(format!(
                    "Failed to decrypt credential: {}",
                    error
                )));
            }
            
            let decrypted = String::from_utf8_lossy(&output.stdout);
            serde_json::from_str(&decrypted).map_err(|e| {
                SshMcpError::CredentialStorage(format!("Invalid credential format: {}", e))
            })
        } else {
            // Legacy unencrypted credential
            serde_json::from_str(&content).map_err(|e| {
                SshMcpError::CredentialStorage(format!("Invalid credential format: {}", e))
            })
        }
    }

    pub fn list_credentials(&self) -> Result<Vec<(String, String, String)>> {
        let mut results = Vec::new();

        if !self.creds_dir.exists() {
            return Ok(results);
        }

        let entries = fs::read_dir(&self.creds_dir).map_err(|e| {
            SshMcpError::CredentialStorage(format!("Failed to read credentials directory: {}", e))
        })?;

        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(cred) = serde_json::from_str::<ExternalCredential>(&content) {
                            results.push((cred.id, cred.cred_type, cred.description));
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

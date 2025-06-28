use crate::error::{Result, SshMcpError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CredentialReference {
    pub id: String,
    pub credential_type: CredentialType,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    Password,
    PrivateKey,
    Passphrase,
}

#[derive(Clone)]
enum StoredCredential {
    Password(String),
    PrivateKey(Vec<u8>),
    Passphrase(String),
}

pub struct CredentialProvider {
    credentials: Arc<Mutex<HashMap<String, StoredCredential>>>,
    references: Arc<Mutex<HashMap<String, CredentialReference>>>,
}

impl CredentialProvider {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
            references: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Store a credential and return a reference ID that can be shared with Claude
    pub async fn store_credential(
        &self,
        credential_type: CredentialType,
        value: String,
        description: String,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();

        let stored = match credential_type {
            CredentialType::Password => StoredCredential::Password(value),
            CredentialType::Passphrase => StoredCredential::Passphrase(value),
            CredentialType::PrivateKey => StoredCredential::PrivateKey(value.into_bytes()),
        };

        let reference = CredentialReference {
            id: id.clone(),
            credential_type,
            description,
        };

        let mut credentials = self.credentials.lock().await;
        let mut references = self.references.lock().await;

        credentials.insert(id.clone(), stored);
        references.insert(id.clone(), reference);

        Ok(id)
    }

    /// Retrieve a password by reference ID (internal use only)
    pub async fn get_password(&self, ref_id: &str) -> Result<String> {
        let credentials = self.credentials.lock().await;

        match credentials.get(ref_id) {
            Some(StoredCredential::Password(pwd)) => Ok(pwd.clone()),
            Some(_) => Err(SshMcpError::CredentialStorage(
                "Reference is not a password".to_string(),
            )),
            None => Err(SshMcpError::CredentialStorage(
                "Credential reference not found".to_string(),
            )),
        }
    }

    /// Retrieve a private key by reference ID (internal use only)
    pub async fn get_private_key(&self, ref_id: &str) -> Result<Vec<u8>> {
        let credentials = self.credentials.lock().await;

        match credentials.get(ref_id) {
            Some(StoredCredential::PrivateKey(key)) => Ok(key.clone()),
            Some(_) => Err(SshMcpError::CredentialStorage(
                "Reference is not a private key".to_string(),
            )),
            None => Err(SshMcpError::CredentialStorage(
                "Credential reference not found".to_string(),
            )),
        }
    }

    /// Retrieve a passphrase by reference ID (internal use only)
    pub async fn get_passphrase(&self, ref_id: &str) -> Result<String> {
        let credentials = self.credentials.lock().await;

        match credentials.get(ref_id) {
            Some(StoredCredential::Passphrase(pass)) => Ok(pass.clone()),
            Some(_) => Err(SshMcpError::CredentialStorage(
                "Reference is not a passphrase".to_string(),
            )),
            None => Err(SshMcpError::CredentialStorage(
                "Credential reference not found".to_string(),
            )),
        }
    }

    /// List all credential references (safe to share with Claude)
    pub async fn list_references(&self) -> Vec<CredentialReference> {
        let references = self.references.lock().await;
        references.values().cloned().collect()
    }

    /// Remove a credential by reference ID
    pub async fn remove_credential(&self, ref_id: &str) -> Result<()> {
        let mut credentials = self.credentials.lock().await;
        let mut references = self.references.lock().await;

        credentials.remove(ref_id);
        references.remove(ref_id);

        Ok(())
    }

    /// Clear all stored credentials
    pub async fn clear_all(&self) {
        let mut credentials = self.credentials.lock().await;
        let mut references = self.references.lock().await;

        credentials.clear();
        references.clear();
    }
}

/// Prompt user for credential input outside of Claude's context
pub async fn prompt_for_credential(
    credential_type: CredentialType,
    prompt_message: &str,
) -> Result<String> {
    use rpassword::prompt_password;

    println!("{}", prompt_message);

    match credential_type {
        CredentialType::Password | CredentialType::Passphrase => {
            prompt_password("Enter credential (hidden): ")
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))
        }
        CredentialType::PrivateKey => {
            // For private keys, we might want to read from a file
            println!("Enter private key path: ");
            let mut path = String::new();
            std::io::stdin()
                .read_line(&mut path)
                .map_err(|e| SshMcpError::CredentialStorage(e.to_string()))?;

            let path = path.trim();
            std::fs::read_to_string(path).map_err(|e| {
                SshMcpError::CredentialStorage(format!("Failed to read private key file: {}", e))
            })
        }
    }
}

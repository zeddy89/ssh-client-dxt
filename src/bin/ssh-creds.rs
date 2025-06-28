use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use dirs::home_dir;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const AES_KEY_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedCredential {
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
    username: String,
    encrypted_credential: String,
    nonce: String,
    salt: String,
    description: String,
    created: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlainCredential {
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
    username: String,
    credential: String,
    description: String,
    created: String,
}

struct CredentialManager {
    creds_dir: PathBuf,
}

impl CredentialManager {
    #[cfg(windows)]
    fn set_windows_permissions(path: &Path) -> Result<()> {
        use std::process::Command;
        
        // Get current username
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "User".to_string());
        
        // Remove inheritance and grant full control only to current user
        // icacls "path" /inheritance:r /grant:r "username:F"
        let output = Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&format!("{}:F", username))
            .output()?;
            
        if !output.status.success() {
            // Fallback: try with takeown first
            Command::new("takeown")
                .arg("/f")
                .arg(path)
                .output()?;
                
            // Retry icacls
            let retry = Command::new("icacls")
                .arg(path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(&format!("{}:F", username))
                .output()?;
                
            if !retry.status.success() {
                eprintln!("Warning: Could not set Windows ACLs. Credentials may not be fully protected.");
            }
        }
        
        Ok(())
    }
    
    fn new() -> Result<Self> {
        let mut creds_dir = home_dir().context("Failed to get home directory")?;
        creds_dir.push(".ssh-mcp");
        creds_dir.push("credentials");

        // Create directory if it doesn't exist
        fs::create_dir_all(&creds_dir)?;

        // Set permissions based on platform
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o700);
            fs::set_permissions(&creds_dir, permissions)?;
        }

        #[cfg(windows)]
        {
            // Set Windows ACLs to restrict access to current user only
            Self::set_windows_permissions(&creds_dir)?;
        }

        Ok(Self { creds_dir })
    }

    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; AES_KEY_SIZE]> {
        let argon2 = Argon2::default();
        let mut key = [0u8; AES_KEY_SIZE];
        
        // Use Argon2 for key derivation
        let salt_str = SaltString::encode_b64(salt).map_err(|e| anyhow::anyhow!("Salt error: {}", e))?;
        let hash = argon2
            .hash_password(password.as_bytes(), &salt_str)
            .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;
        
        // Extract the hash and use first 32 bytes as key
        let hash_bytes = hash.hash.context("No hash found")?;
        let hash_raw = hash_bytes.as_bytes();
        
        if hash_raw.len() < AES_KEY_SIZE {
            return Err(anyhow::anyhow!("Hash too short"));
        }
        
        key.copy_from_slice(&hash_raw[..AES_KEY_SIZE]);
        Ok(key)
    }

    fn encrypt_data(data: &[u8], password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Generate salt and nonce
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes().to_vec();
        
        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Derive key from password
        let key = Self::derive_key(password, &salt_bytes)?;
        
        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        Ok((ciphertext, nonce_bytes.to_vec(), salt_bytes))
    }

    fn decrypt_data(ciphertext: &[u8], password: &str, nonce: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Derive key from password
        let key = Self::derive_key(password, salt)?;
        
        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed - wrong password?"))?;

        Ok(plaintext)
    }

    fn store_credential(&self, password: &str) -> Result<()> {
        println!("SSH MCP Credential Store (Encrypted)");
        println!("====================================");
        
        // Get description
        print!("Enter description: ");
        io::stdout().flush()?;
        let mut description = String::new();
        io::stdin().read_line(&mut description)?;
        let description = description.trim().to_string();
        
        // Get credential type
        println!("\nCredential type:");
        println!("1) Password");
        println!("2) Private Key Path");
        println!("3) Private Key Content");
        print!("Select (1-3): ");
        io::stdout().flush()?;
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        let (cred_type, username, credential) = match choice.trim() {
            "1" => {
                print!("Enter username: ");
                io::stdout().flush()?;
                let mut username = String::new();
                io::stdin().read_line(&mut username)?;
                
                print!("Enter password: ");
                io::stdout().flush()?;
                let credential = read_password()?;
                
                ("password".to_string(), username.trim().to_string(), credential)
            }
            "2" => {
                print!("Enter username: ");
                io::stdout().flush()?;
                let mut username = String::new();
                io::stdin().read_line(&mut username)?;
                
                print!("Enter private key path: ");
                io::stdout().flush()?;
                let mut path = String::new();
                io::stdin().read_line(&mut path)?;
                let path = path.trim();
                
                // Verify file exists
                if !Path::new(path).exists() {
                    return Err(anyhow::anyhow!("File not found: {}", path));
                }
                
                ("keypath".to_string(), username.trim().to_string(), path.to_string())
            }
            "3" => {
                print!("Enter username: ");
                io::stdout().flush()?;
                let mut username = String::new();
                io::stdin().read_line(&mut username)?;
                
                println!("Paste private key content (press Enter then Ctrl+D when done):");
                let mut credential = String::new();
                io::stdin().read_to_string(&mut credential)?;
                
                ("keyfile".to_string(), username.trim().to_string(), credential)
            }
            _ => return Err(anyhow::anyhow!("Invalid selection")),
        };
        
        // Generate reference ID
        let ref_id = format!("ref_{}", Uuid::new_v4().as_simple());
        
        // Encrypt the credential
        let (encrypted, nonce, salt) = Self::encrypt_data(credential.as_bytes(), password)?;
        
        // Create encrypted credential
        let encrypted_cred = EncryptedCredential {
            id: ref_id.clone(),
            cred_type,
            username,
            encrypted_credential: BASE64.encode(&encrypted),
            nonce: BASE64.encode(&nonce),
            salt: BASE64.encode(&salt),
            description,
            created: Utc::now().to_rfc3339(),
        };
        
        // Save to file
        let cred_file = self.creds_dir.join(format!("{}.json", ref_id));
        let json = serde_json::to_string_pretty(&encrypted_cred)?;
        
        let mut file = File::create(&cred_file)?;
        file.write_all(json.as_bytes())?;
        
        // Set file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(&cred_file, permissions)?;
        }
        
        #[cfg(windows)]
        {
            Self::set_windows_permissions(&cred_file)?;
        }
        
        println!("\n✓ Credential stored successfully (encrypted)!");
        println!("Reference ID: {}", ref_id);
        println!("\nUse this reference ID in Claude with ssh_connect:");
        println!("- credentialRef: {}", ref_id);
        
        Ok(())
    }

    fn list_credentials(&self) -> Result<()> {
        println!("Stored Credentials");
        println!("==================");
        
        let entries = fs::read_dir(&self.creds_dir)?;
        let mut found = false;
        
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                
                // Try to parse as encrypted first, then as plain
                if content.contains("\"encrypted_credential\"") {
                    if let Ok(cred) = serde_json::from_str::<EncryptedCredential>(&content) {
                        found = true;
                        println!("\nID: {}", cred.id);
                        println!("  Type: {}", cred.cred_type);
                        println!("  Username: {}", cred.username);
                        println!("  Description: {}", cred.description);
                        println!("  Created: {}", cred.created);
                        println!("  Status: Encrypted ✓");
                    }
                } else {
                    // Legacy plain credential
                    if let Ok(cred) = serde_json::from_str::<PlainCredential>(&content) {
                        found = true;
                        println!("\nID: {}", cred.id);
                        println!("  Type: {}", cred.cred_type);
                        println!("  Username: {}", cred.username);
                        println!("  Description: {}", cred.description);
                        println!("  Created: {}", cred.created);
                        println!("  Status: ⚠️  UNENCRYPTED (consider re-storing with encryption)");
                    }
                }
            }
        }
        
        if !found {
            println!("No credentials stored.");
        }
        
        Ok(())
    }

    fn delete_credential(&self) -> Result<()> {
        print!("Enter reference ID to delete: ");
        io::stdout().flush()?;
        let mut ref_id = String::new();
        io::stdin().read_line(&mut ref_id)?;
        let ref_id = ref_id.trim();
        
        let cred_file = self.creds_dir.join(format!("{}.json", ref_id));
        
        if !cred_file.exists() {
            return Err(anyhow::anyhow!("Credential not found: {}", ref_id));
        }
        
        // Show credential details
        let content = fs::read_to_string(&cred_file)?;
        let cred: EncryptedCredential = serde_json::from_str(&content)?;
        
        println!("Delete credential: {}?", cred.description);
        print!("Confirm (y/N): ");
        io::stdout().flush()?;
        
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm)?;
        
        if confirm.trim().to_lowercase() == "y" {
            fs::remove_file(&cred_file)?;
            println!("✓ Credential deleted");
        } else {
            println!("Cancelled");
        }
        
        Ok(())
    }

    fn get_master_password_for_export(&self) -> Result<String> {
        // 1. Try environment variable first
        if let Ok(password) = std::env::var("SSH_MCP_MASTER_PASSWORD") {
            return Ok(password);
        }

        // 2. Try macOS keychain
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            let output = Command::new("security")
                .args(&["find-generic-password", "-a", "ssh-mcp", "-s", "master-password", "-w"])
                .output()
                .map_err(|e| anyhow::anyhow!("Failed to run security command: {}", e))?;
            
            if output.status.success() {
                let password = String::from_utf8_lossy(&output.stdout);
                return Ok(password.trim().to_string());
            }
        }

        // 3. Try reading from stdin (for backward compatibility)
        let password = read_password()?;
        Ok(password)
    }
    
    fn export_for_mcp(&self, ref_id: &str, password: &str) -> Result<()> {
        let cred_file = self.creds_dir.join(format!("{}.json", ref_id));
        
        if !cred_file.exists() {
            return Err(anyhow::anyhow!("Credential not found: {}", ref_id));
        }
        
        let content = fs::read_to_string(&cred_file)?;
        let encrypted_cred: EncryptedCredential = serde_json::from_str(&content)?;
        
        // Decrypt the credential
        let encrypted_bytes = BASE64.decode(&encrypted_cred.encrypted_credential)?;
        let nonce_bytes = BASE64.decode(&encrypted_cred.nonce)?;
        let salt_bytes = BASE64.decode(&encrypted_cred.salt)?;
        
        let decrypted = Self::decrypt_data(&encrypted_bytes, password, &nonce_bytes, &salt_bytes)?;
        let credential = String::from_utf8(decrypted)?;
        
        // Create plain credential for MCP
        let plain_cred = PlainCredential {
            id: encrypted_cred.id,
            cred_type: encrypted_cred.cred_type,
            username: encrypted_cred.username,
            credential,
            description: encrypted_cred.description,
            created: encrypted_cred.created,
        };
        
        // Output as JSON for MCP to read
        println!("{}", serde_json::to_string(&plain_cred)?);
        
        Ok(())
    }
}

fn show_help() {
    println!("SSH MCP Credential Helper (Encrypted)");
    println!();
    println!("Usage: ssh-creds [command]");
    println!();
    println!("Commands:");
    println!("  store    Store a new credential (encrypted)");
    println!("  list     List all stored credentials");
    println!("  delete   Delete a credential");
    println!("  export   Export credential for MCP (internal use)");
    println!("  help     Show this help message");
    println!();
    println!("This tool securely stores SSH credentials with encryption.");
    println!("All credentials are encrypted with AES-256-GCM using your master password.");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    
    let manager = CredentialManager::new()?;
    
    match command {
        "store" => {
            println!("Enter master password for encryption:");
            let password = read_password()?;
            manager.store_credential(&password)?;
        }
        "list" => {
            manager.list_credentials()?;
        }
        "delete" => {
            manager.delete_credential()?;
        }
        "export" => {
            // Internal command used by MCP
            if args.len() < 3 {
                return Err(anyhow::anyhow!("Usage: ssh-creds export <ref_id>"));
            }
            let ref_id = &args[2];
            // Get password from various sources (env, keychain, or stdin)
            let password = manager.get_master_password_for_export()?;
            manager.export_for_mcp(ref_id, &password)?;
        }
        "help" | "--help" | "-h" => {
            show_help();
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            show_help();
            std::process::exit(1);
        }
    }
    
    Ok(())
}
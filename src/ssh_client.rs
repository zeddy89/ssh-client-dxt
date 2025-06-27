use crate::config::SshConfig;
use crate::error::{Result, SshMcpError};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use tracing::{debug, info};

pub struct SshClient;

impl SshClient {
    pub fn connect(config: &SshConfig) -> Result<Session> {
        info!("Connecting to {}@{}:{}", config.username, config.host, config.port);
        
        // Establish TCP connection
        let tcp = TcpStream::connect((config.host.as_str(), config.port))
            .map_err(|e| SshMcpError::SshConnection(format!("TCP connection failed: {}", e)))?;
        
        // Create SSH session
        let mut session = Session::new()
            .map_err(|e| SshMcpError::SshConnection(format!("Session creation failed: {}", e)))?;
        
        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|e| SshMcpError::SshConnection(format!("SSH handshake failed: {}", e)))?;
        
        // Get host key for verification
        let host_key = session.host_key()
            .ok_or_else(|| SshMcpError::HostVerificationFailed("No host key available".to_string()))?;
        
        let fingerprint = Self::calculate_fingerprint(host_key.0);
        debug!("Host key fingerprint: {}", fingerprint);
        
        // Authenticate
        Self::authenticate(&mut session, config)?;
        
        info!("Successfully connected to {}@{}", config.username, config.host);
        Ok(session)
    }
    
    fn authenticate(session: &mut Session, config: &SshConfig) -> Result<()> {
        // Try key-based authentication first
        if let Some(key_path) = &config.private_key_path {
            debug!("Attempting key-based authentication with {:?}", key_path);
            
            let result = if let Some(passphrase) = &config.passphrase {
                session.userauth_pubkey_file(
                    &config.username,
                    None,
                    key_path,
                    Some(passphrase)
                )
            } else {
                session.userauth_pubkey_file(
                    &config.username,
                    None,
                    key_path,
                    None
                )
            };
            
            if result.is_ok() && session.authenticated() {
                debug!("Key-based authentication successful");
                return Ok(());
            }
        }
        
        // Try password authentication
        if let Some(password) = &config.password {
            debug!("Attempting password authentication");
            session.userauth_password(&config.username, password)
                .map_err(|e| SshMcpError::AuthenticationFailed(e.to_string()))?;
            
            if session.authenticated() {
                debug!("Password authentication successful");
                return Ok(());
            }
        }
        
        // Try keyboard-interactive
        debug!("Attempting keyboard-interactive authentication");
        if let Some(password) = &config.password {
            struct KbdPrompt<'a> {
                password: &'a str,
            }
            
            impl<'a> ssh2::KeyboardInteractivePrompt for KbdPrompt<'a> {
                fn prompt(&mut self, _: &str, _: &str, _: &[ssh2::Prompt]) -> Vec<String> {
                    vec![self.password.to_string()]
                }
            }
            
            let mut prompt = KbdPrompt { password };
            session.userauth_keyboard_interactive(&config.username, &mut prompt)
                .map_err(|e| SshMcpError::AuthenticationFailed(e.to_string()))?;
        }
        
        if !session.authenticated() {
            return Err(SshMcpError::AuthenticationFailed(
                "All authentication methods failed".to_string()
            ));
        }
        
        Ok(())
    }
    
    pub fn calculate_fingerprint(host_key: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        use base64::{Engine as _, engine::general_purpose};
        let mut hasher = Sha256::new();
        hasher.update(host_key);
        let result = hasher.finalize();
        general_purpose::STANDARD.encode(result)
    }
    
    pub fn execute_command(session: &Session, command: &str) -> Result<(String, String, i32)> {
        debug!("Executing command: {}", command);
        
        let mut channel = session.channel_session()
            .map_err(|e| SshMcpError::SshConnection(format!("Channel creation failed: {}", e)))?;
        
        channel.exec(command)
            .map_err(|e| SshMcpError::SshConnection(format!("Command execution failed: {}", e)))?;
        
        let mut stdout = String::new();
        channel.read_to_string(&mut stdout)
            .map_err(|e| SshMcpError::SshConnection(format!("Failed to read stdout: {}", e)))?;
        
        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr)
            .map_err(|e| SshMcpError::SshConnection(format!("Failed to read stderr: {}", e)))?;
        
        channel.wait_close()
            .map_err(|e| SshMcpError::SshConnection(format!("Failed to close channel: {}", e)))?;
        
        let exit_code = channel.exit_status().unwrap_or(-1);
        
        debug!("Command completed with exit code: {}", exit_code);
        Ok((stdout, stderr, exit_code))
    }
    
    pub fn upload_file(session: &Session, local_path: &Path, remote_path: &str) -> Result<()> {
        info!("Uploading {:?} to {}", local_path, remote_path);
        
        let sftp = session.sftp()
            .map_err(|e| SshMcpError::FileOperation(format!("SFTP initialization failed: {}", e)))?;
        
        let mut local_file = std::fs::File::open(local_path)
            .map_err(|e| SshMcpError::FileOperation(format!("Failed to open local file: {}", e)))?;
        
        let mut remote_file = sftp.create(Path::new(remote_path))
            .map_err(|e| SshMcpError::FileOperation(format!("Failed to create remote file: {}", e)))?;
        
        std::io::copy(&mut local_file, &mut remote_file)
            .map_err(|e| SshMcpError::FileOperation(format!("File transfer failed: {}", e)))?;
        
        info!("File uploaded successfully");
        Ok(())
    }
    
    pub fn download_file(session: &Session, remote_path: &str, local_path: &Path) -> Result<()> {
        info!("Downloading {} to {:?}", remote_path, local_path);
        
        let sftp = session.sftp()
            .map_err(|e| SshMcpError::FileOperation(format!("SFTP initialization failed: {}", e)))?;
        
        let mut remote_file = sftp.open(Path::new(remote_path))
            .map_err(|e| SshMcpError::FileOperation(format!("Failed to open remote file: {}", e)))?;
        
        let mut local_file = std::fs::File::create(local_path)
            .map_err(|e| SshMcpError::FileOperation(format!("Failed to create local file: {}", e)))?;
        
        std::io::copy(&mut remote_file, &mut local_file)
            .map_err(|e| SshMcpError::FileOperation(format!("File transfer failed: {}", e)))?;
        
        info!("File downloaded successfully");
        Ok(())
    }
}
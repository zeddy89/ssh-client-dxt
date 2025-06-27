#[cfg(test)]
mod tests {
    use crate::tools;
    use crate::credential_provider::{CredentialProvider, CredentialType};
    use crate::session_manager::SessionManager;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_ssh_credential_store_list() {
        let provider = Arc::new(CredentialProvider::new());
        
        // Store some credentials first
        provider.store_credential(
            CredentialType::Password,
            "test123".to_string(),
            "Test credential".to_string()
        ).await.unwrap();
        
        // Test list action
        let params = json!({
            "action": "list"
        });
        
        let result = tools::ssh_credential_store(params, provider.clone()).await.unwrap();
        
        assert_eq!(result["action"], "list");
        assert!(result["credentials"].is_array());
        assert_eq!(result["credentials"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_ssh_list_sessions_empty() {
        let manager = Arc::new(SessionManager::new(10, Duration::from_secs(1800)));
        
        let result = tools::ssh_list_sessions(manager).await.unwrap();
        
        assert!(result["sessions"].is_array());
        assert_eq!(result["sessions"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_ssh_verify_host() {
        let known_hosts = Arc::new(Mutex::new(HashMap::new()));
        
        // Add a known host
        known_hosts.lock().await.insert(
            "example.com:22".to_string(),
            "SHA256:abcd1234".to_string()
        );
        
        // Test verify action with matching fingerprint
        let params = json!({
            "host": "example.com",
            "port": 22,
            "fingerprint": "SHA256:abcd1234",
            "action": "verify"
        });
        
        let result = tools::ssh_verify_host(params, known_hosts.clone()).await.unwrap();
        
        assert_eq!(result["verified"], true);
        assert_eq!(result["host"], "example.com");
        assert_eq!(result["port"], 22);
    }

    #[tokio::test]
    async fn test_ssh_verify_host_mismatch() {
        let known_hosts = Arc::new(Mutex::new(HashMap::new()));
        
        // Add a known host
        known_hosts.lock().await.insert(
            "example.com:22".to_string(),
            "SHA256:abcd1234".to_string()
        );
        
        // Test verify action with non-matching fingerprint
        let params = json!({
            "host": "example.com",
            "port": 22,
            "fingerprint": "SHA256:different",
            "action": "verify"
        });
        
        let result = tools::ssh_verify_host(params, known_hosts.clone()).await.unwrap();
        
        assert_eq!(result["verified"], false);
        assert_eq!(result["knownFingerprint"], "SHA256:abcd1234");
    }

    #[tokio::test]
    async fn test_ssh_config_manage_list() {
        let configs = Arc::new(Mutex::new(HashMap::new()));
        
        // Add a test config
        configs.lock().await.insert(
            "test-server".to_string(),
            crate::config::SshConfig {
                host: "test.example.com".to_string(),
                port: 22,
                username: "testuser".to_string(),
                password: None,
                private_key_path: None,
                passphrase: None,
                strict_host_checking: true,
                description: Some("Test server".to_string()),
            }
        );
        
        // Test list action
        let params = json!({
            "action": "list"
        });
        
        let result = tools::ssh_config_manage(params, configs).await.unwrap();
        
        assert!(result["configs"].is_array());
        let config_list = result["configs"].as_array().unwrap();
        assert_eq!(config_list.len(), 1);
        assert_eq!(config_list[0]["name"], "test-server");
        assert_eq!(config_list[0]["host"], "test.example.com");
    }

    #[test]
    fn test_tool_definitions() {
        let tools = tools::get_tool_definitions();
        
        // Verify we have all expected tools
        let tool_names: Vec<String> = tools.iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        
        assert!(tool_names.contains(&"ssh_connect".to_string()));
        assert!(tool_names.contains(&"ssh_execute".to_string()));
        assert!(tool_names.contains(&"ssh_disconnect".to_string()));
        assert!(tool_names.contains(&"ssh_list_sessions".to_string()));
        assert!(tool_names.contains(&"ssh_upload_file".to_string()));
        assert!(tool_names.contains(&"ssh_download_file".to_string()));
        assert!(tool_names.contains(&"ssh_port_forward".to_string()));
        assert!(tool_names.contains(&"ssh_manage_keys".to_string()));
        assert!(tool_names.contains(&"ssh_verify_host".to_string()));
        assert!(tool_names.contains(&"ssh_config_manage".to_string()));
        assert!(tool_names.contains(&"ssh_credential_store".to_string()));
        
        // Verify tool count
        assert_eq!(tools.len(), 11);
    }
}
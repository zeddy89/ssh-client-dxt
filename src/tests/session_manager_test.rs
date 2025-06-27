#[cfg(test)]
mod tests {
    use crate::config::SshConfig;
    use crate::session_manager::{SessionManager, SshSession};
    use ssh2::Session;
    use std::time::Duration;
    use tokio;

    fn create_mock_config() -> SshConfig {
        SshConfig {
            host: "test.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("password".to_string()),
            private_key_path: None,
            passphrase: None,
            strict_host_checking: false,
            description: Some("Test connection".to_string()),
        }
    }

    #[tokio::test]
    async fn test_add_session() {
        let manager = SessionManager::new(10, Duration::from_secs(1800));

        // Create a mock session (in real tests, we'd use a mock SSH session)
        let config = create_mock_config();
        let session = Session::new().unwrap();
        let ssh_session = SshSession::new(config.clone(), session);

        // Add session
        let session_id = manager.add_session(ssh_session).await.unwrap();
        assert!(!session_id.is_empty());

        // Verify session exists
        let sessions = manager.list_sessions().await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].0, session_id);
        assert_eq!(sessions[0].1.host, "test.example.com");
    }

    #[tokio::test]
    async fn test_max_sessions_limit() {
        let manager = SessionManager::new(2, Duration::from_secs(1800));

        // Add first session
        let config = create_mock_config();
        let session1 = SshSession::new(config.clone(), Session::new().unwrap());
        manager.add_session(session1).await.unwrap();

        // Add second session
        let session2 = SshSession::new(config.clone(), Session::new().unwrap());
        manager.add_session(session2).await.unwrap();

        // Third session should fail
        let session3 = SshSession::new(config, Session::new().unwrap());
        let result = manager.add_session(session3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_session() {
        let manager = SessionManager::new(10, Duration::from_secs(1800));

        // Add session
        let config = create_mock_config();
        let ssh_session = SshSession::new(config, Session::new().unwrap());
        let session_id = manager.add_session(ssh_session).await.unwrap();

        // Remove session
        manager.remove_session(&session_id).await.unwrap();

        // Verify it's gone
        let sessions = manager.list_sessions().await;
        assert_eq!(sessions.len(), 0);

        // Removing again should fail
        assert!(manager.remove_session(&session_id).await.is_err());
    }

    #[tokio::test]
    async fn test_session_activity_update() {
        let manager = SessionManager::new(10, Duration::from_secs(1800));

        // Add session
        let config = create_mock_config();
        let ssh_session = SshSession::new(config, Session::new().unwrap());
        let session_id = manager.add_session(ssh_session).await.unwrap();

        // Get session (updates activity)
        manager.get_session(&session_id).await.unwrap();

        // Session should still exist
        let sessions = manager.list_sessions().await;
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_clear_all_sessions() {
        let manager = SessionManager::new(10, Duration::from_secs(1800));

        // Add multiple sessions
        let config = create_mock_config();
        for _ in 0..3 {
            let ssh_session = SshSession::new(config.clone(), Session::new().unwrap());
            manager.add_session(ssh_session).await.unwrap();
        }

        // Verify they exist
        assert_eq!(manager.list_sessions().await.len(), 3);

        // Clear all
        manager.clear_all_sessions().await;

        // Verify all are gone
        assert_eq!(manager.list_sessions().await.len(), 0);
    }
}

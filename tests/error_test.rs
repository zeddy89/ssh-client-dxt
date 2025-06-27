#[cfg(test)]
mod tests {
    use crate::error::{SshMcpError, Result};

    #[test]
    fn test_error_display() {
        let err = SshMcpError::SessionNotFound("test-session-123".to_string());
        assert_eq!(err.to_string(), "Session not found: test-session-123");
        
        let err = SshMcpError::MaxSessionsReached(5);
        assert_eq!(err.to_string(), "Maximum sessions reached: 5");
        
        let err = SshMcpError::AuthenticationFailed("Invalid password".to_string());
        assert_eq!(err.to_string(), "Authentication failed: Invalid password");
    }

    #[test]
    fn test_error_conversion() {
        // Test From<std::io::Error>
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let ssh_err: SshMcpError = io_err.into();
        assert!(matches!(ssh_err, SshMcpError::Io(_)));
        
        // Test From<serde_json::Error>
        let json_str = r#"{"invalid": json}"#;
        let json_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let ssh_err: SshMcpError = json_err.into();
        assert!(matches!(ssh_err, SshMcpError::Json(_)));
    }

    #[test]
    fn test_result_type() {
        fn test_function() -> Result<String> {
            Ok("success".to_string())
        }
        
        fn test_error_function() -> Result<String> {
            Err(SshMcpError::Validation("Test error".to_string()))
        }
        
        assert!(test_function().is_ok());
        assert!(test_error_function().is_err());
    }
}
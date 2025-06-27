#[cfg(test)]
mod tests {
    use crate::credential_provider::{CredentialProvider, CredentialType};
    use tokio;

    #[tokio::test]
    async fn test_store_and_retrieve_password() {
        let provider = CredentialProvider::new();
        
        // Store a password
        let ref_id = provider.store_credential(
            CredentialType::Password,
            "test_password123".to_string(),
            "Test password".to_string()
        ).await.unwrap();
        
        // Retrieve the password
        let retrieved = provider.get_password(&ref_id).await.unwrap();
        assert_eq!(retrieved, "test_password123");
        
        // List references
        let refs = provider.list_references().await;
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].id, ref_id);
        assert_eq!(refs[0].description, "Test password");
    }

    #[tokio::test]
    async fn test_store_and_retrieve_passphrase() {
        let provider = CredentialProvider::new();
        
        // Store a passphrase
        let ref_id = provider.store_credential(
            CredentialType::Passphrase,
            "secret_passphrase".to_string(),
            "SSH key passphrase".to_string()
        ).await.unwrap();
        
        // Retrieve the passphrase
        let retrieved = provider.get_passphrase(&ref_id).await.unwrap();
        assert_eq!(retrieved, "secret_passphrase");
    }

    #[tokio::test]
    async fn test_remove_credential() {
        let provider = CredentialProvider::new();
        
        // Store a credential
        let ref_id = provider.store_credential(
            CredentialType::Password,
            "temp_password".to_string(),
            "Temporary".to_string()
        ).await.unwrap();
        
        // Remove it
        provider.remove_credential(&ref_id).await.unwrap();
        
        // Verify it's gone
        let refs = provider.list_references().await;
        assert_eq!(refs.len(), 0);
        
        // Trying to retrieve should fail
        assert!(provider.get_password(&ref_id).await.is_err());
    }

    #[tokio::test]
    async fn test_credential_type_mismatch() {
        let provider = CredentialProvider::new();
        
        // Store a password
        let ref_id = provider.store_credential(
            CredentialType::Password,
            "password123".to_string(),
            "Password".to_string()
        ).await.unwrap();
        
        // Try to retrieve as passphrase (should fail)
        assert!(provider.get_passphrase(&ref_id).await.is_err());
    }

    #[tokio::test]
    async fn test_clear_all_credentials() {
        let provider = CredentialProvider::new();
        
        // Store multiple credentials
        provider.store_credential(
            CredentialType::Password,
            "pass1".to_string(),
            "First".to_string()
        ).await.unwrap();
        
        provider.store_credential(
            CredentialType::Passphrase,
            "pass2".to_string(),
            "Second".to_string()
        ).await.unwrap();
        
        // Clear all
        provider.clear_all().await;
        
        // Verify all are gone
        let refs = provider.list_references().await;
        assert_eq!(refs.len(), 0);
    }
}
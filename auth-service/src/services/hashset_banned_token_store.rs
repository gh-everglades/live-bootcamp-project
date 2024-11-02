use std::collections::HashSet;
use crate::domain::{BannedTokenStore, UserStoreError};
use std::sync::Mutex;


// Create a concrete banned token store implementation that uses a HashSet to store tokens. 
// The concrete type should be a struct called HashsetBannedTokenStore. 
#[derive(Default)]
pub struct HashsetBannedTokenStore {
    pub tokens: Mutex<HashSet<String>>,
}

// Implement the BannedTokenStore trait for HashsetBannedTokenStore.
#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&self, token: String) -> Result<(), UserStoreError> {
        let mut tokens = self.tokens.lock().map_err(|_| UserStoreError::UnexpectedError)?;
        tokens.insert(token);
        Ok(())
    }

    async fn check_token(&self, token: String) -> Result<bool, UserStoreError> {
        let tokens = self.tokens.lock().map_err(|_| UserStoreError::UnexpectedError)?;
        Ok(tokens.contains(&token))
    }
}

// Add unit tests for your `HashsetBannedTokenStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_check_tokens() {
        let store = HashsetBannedTokenStore::default();
        let token1 = "abc123".to_string();
        let token2 = "def456".to_string();
        store.store_token(token1.clone()).await.unwrap();
        store.store_token(token2.clone()).await.unwrap();
        assert_eq!(store.check_token(token1.clone()).await, Ok(true));
        assert_eq!(store.check_token(token2.clone()).await, Ok(true));
    }

    #[tokio::test]
    async fn test_check_non_existing_token() {
        let store = HashsetBannedTokenStore::default();
        let token1 = "abc123".to_string();
        assert_eq!(store.check_token(token1.clone()).await, Ok(false));
        
    }
}
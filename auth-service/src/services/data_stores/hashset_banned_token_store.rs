use std::collections::HashSet;
use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};


// Create a concrete banned token store implementation that uses a HashSet to store tokens. 
// The concrete type should be a struct called HashsetBannedTokenStore. 
#[derive(Default)]
pub struct HashsetBannedTokenStore {
    pub tokens: HashSet<String>,
}

// Implement the BannedTokenStore trait for HashsetBannedTokenStore.
#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        //let mut tokens = self.tokens.lock().map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        self.tokens.insert(token.expose_secret().to_string());
        Ok(())
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        //let tokens = self.tokens.lock().map_err(|_| BannedTokenStoreError::TokenDoNotExist)?;
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

// Add unit tests for your `HashsetBannedTokenStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_check_tokens() {
        let mut store = HashsetBannedTokenStore::default();
        let token1 = Secret::new("abc123".to_string());
        let token2 = Secret::new("def456".to_string());
        store.add_token(token1.clone()).await.unwrap();
        store.add_token(token2.clone()).await.unwrap();
        assert_eq!(store.contains_token(&token1).await, Ok(true));
        assert_eq!(store.contains_token(&token2).await, Ok(true));
    }

    #[tokio::test]
    async fn test_check_non_existing_token() {
        let store = HashsetBannedTokenStore::default();
        let token1 = Secret::new("abc123".to_string());
        assert_eq!(store.contains_token(&token1).await, Ok(false));
        
    }
}
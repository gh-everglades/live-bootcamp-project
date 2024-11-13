use std::collections::HashMap;

use crate::domain::{
    {LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};


#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

// implement TwoFACodeStore for HashmapTwoFACodeStore
#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes.get(email).cloned().ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;
    use crate::domain::Email;

    #[tokio::test]
    async fn test_add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let code = TwoFACode::default();
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        
        let login_attempt_id = LoginAttemptId::default();
        store.add_code(email.clone(), login_attempt_id.clone(), code.clone()).await.unwrap();
        assert_eq!(store.get_code(&email).await.unwrap(), (login_attempt_id, code));
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let code = TwoFACode::default();
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        store.add_code(email.clone(), login_attempt_id, code.clone()).await.unwrap();
        store.remove_code(&email).await.unwrap();
        assert_eq!(store.get_code(&email).await, Err(TwoFACodeStoreError::LoginAttemptIdNotFound));
    }

    #[tokio::test]
    async fn test_get_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let code = TwoFACode::default();
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        store.add_code(email.clone(), login_attempt_id.clone(), code.clone()).await.unwrap();
        assert_eq!(store.get_code(&email).await.unwrap(), (login_attempt_id, code));
    }
}
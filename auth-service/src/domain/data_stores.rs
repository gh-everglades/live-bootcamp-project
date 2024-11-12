use super::{Email, Password, User};
use uuid::Uuid;
use rand::Rng;
use color_eyre::eyre::Report;
use thiserror::Error;


#[async_trait::async_trait]
pub trait UserStore: {
    // Add the `add_user`, `get_user`, and `validate_user` methods.
    // Make sure all methods are async so we can use async user stores in the future
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError>;
}

// Add a BannedTokenStore trait
//The trait should define one method for storing tokens (as Strings) and another method for checking
// if a token exists within the banned token store. It's up to you to determine the 
// exact API (input parameters & return values).
#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: String) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreError {
    TokenDoNotExist,
    UnexpectedError,
}

// Add a UserStoreError enum to auth-service/src/domain/errors.rs
#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}
impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}


// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        match Uuid::parse_str(&id) {
            Ok(_) => Ok(Self(id)),
            Err(_) => Err("Invalid UUID format".to_string()),
        }
    }
}
impl Default for LoginAttemptId {
    fn default() -> Self {
        // Use the `uuid` crate to generate a random version 4 UUID
        let id = Uuid::new_v4();
        LoginAttemptId(id.to_string())
    }
}

// Implement AsRef<str> for LoginAttemptId
impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        // Ensure `code` is a valid 6-digit code
        let code_len = code.len();
        if code_len!= 6 {
            return Err("Invalid 2FA code length".to_string());
        }
        // Ensure `code` contains only digits
        if!code.chars().all(|c| c.is_digit(10)) {
            return Err("Invalid 2FA code contains non-digit characters".to_string());
        }
        // Return the parsed TwoFACode instance if validation passes
        Ok(Self(code))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let code = rand::thread_rng().gen_range(100000..1000000);
        TwoFACode(code.to_string())
    }
}

// Implement AsRef<str> for TwoFACode
impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
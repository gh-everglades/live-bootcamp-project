use super::{Email, Password, User};

#[async_trait::async_trait]
pub trait UserStore {
    // Add the `add_user`, `get_user`, and `validate_user` methods.
    // Make sure all methods are async so we can use async user stores in the future
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: Email) -> Result<&User, UserStoreError>;
    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError>;
}

// Add a BannedTokenStore trait
//The trait should define one method for storing tokens (as Strings) and another method for checking
// if a token exists within the banned token store. It's up to you to determine the 
// exact API (input parameters & return values).
#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn store_token(&self, token: String) -> Result<(), UserStoreError>;
    async fn check_token(&self, token: String) -> Result<bool, UserStoreError>;
}

// Add a UserStoreError enum to auth-service/src/domain/errors.rs
#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}
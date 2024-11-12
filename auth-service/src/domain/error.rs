use crate::domain::data_stores::UserStoreError;
use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl From<UserStoreError> for AuthAPIError {
    fn from(error: UserStoreError) -> Self {
        match error {
            UserStoreError::UserNotFound => AuthAPIError::IncorrectCredentials,
            UserStoreError::InvalidCredentials => AuthAPIError::InvalidCredentials,
            UserStoreError::UserAlreadyExists => AuthAPIError::UserAlreadyExists,
            UserStoreError::UnexpectedError(e) => AuthAPIError::UnexpectedError(e),
        }
    }
}
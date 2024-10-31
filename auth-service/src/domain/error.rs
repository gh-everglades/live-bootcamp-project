use crate::domain::data_stores::UserStoreError;

#[derive(Debug)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    UnexpectedError,
    IncorrectCredentials,
    MissingToken,
    InvalidToken,
}

impl From<UserStoreError> for AuthAPIError {
    fn from(error: UserStoreError) -> Self {
        match error {
            UserStoreError::UserNotFound => AuthAPIError::IncorrectCredentials,
            UserStoreError::InvalidCredentials => AuthAPIError::InvalidCredentials,
            UserStoreError::UserAlreadyExists => AuthAPIError::UserAlreadyExists,
            UserStoreError::UnexpectedError => AuthAPIError::UnexpectedError,
        }
    }
}
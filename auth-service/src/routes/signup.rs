use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::result::Result;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User},
};

#[tracing::instrument(name = "Signup", skip_all, err(Debug))] // New!
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
    ) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email.clone())?;
    let password = Password::parse(request.password)?;

    let user = User::new(email.clone(), password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    // early return AuthAPIError::UserAlreadyExists if email exists in user_store.
    if user_store.get_user(email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    // instead of using unwrap, early return AuthAPIError::UnexpectedError if add_user() fails.
    user_store.add_user(user).await.map_err(|_| AuthAPIError::UnexpectedError)?;

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::User};

pub async fn signup(
    // TODO: Use Axum's state extractor to pass in AppState
    State(state): State<AppState>,
    // Extract the `Json` body from the request
    Json(request): Json<SignupRequest>) -> impl IntoResponse {
    // Create a new `User` instance using data in the `request`
    let user = User {
        email: request.email,
        password: request.password,
        requires_2fa: request.requires_2fa,
    };

    let mut user_store = state.user_store.write().await;

    // TODO: Add `user` to the `user_store`. Simply unwrap the returned `Result` enum type for now.
    user_store.add_user(user).unwrap();

    // Return a 201 Created response with a JSON body containing a success message
    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    (StatusCode::CREATED, response)
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

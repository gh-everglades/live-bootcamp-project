use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use secrecy::Secret;
use serde::Deserialize;

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

#[tracing::instrument(name = "Verify Token", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    
    validate_token(&request.token, state.banned_token_store).await.map_err(|_| AuthAPIError::InvalidToken)?;

    Ok((StatusCode::OK, "Token verified successfully!".to_string()  ))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: Secret<String>
}
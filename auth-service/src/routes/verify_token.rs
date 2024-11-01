use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{domain::AuthAPIError, utils::auth::validate_token};

pub async fn verify_token(
    Json(request): Json<VerifyRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    
    validate_token(request.token.as_str()).await.map_err(|_| AuthAPIError::InvalidToken)?;

    Ok((StatusCode::OK, "Token verified successfully!".to_string()  ))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: String
}
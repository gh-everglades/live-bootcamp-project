/*use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode}, utils::auth::generate_auth_cookie};

pub async fn verify_2fa(
    State(state): State<AppState>, // New!
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    
    // Validate the email in `request`
    let email = Email::parse(request.email)
                .map_err(|_| AuthAPIError::InvalidCredentials)?;

    // Validate the login attempt ID in `request`
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
                .map_err(|_| AuthAPIError::InvalidCredentials)?;

    // Validate the 2FA code in `request`
    let two_fa_code = TwoFACode::parse(request.two_fa_code)
                .map_err(|_| AuthAPIError::InvalidCredentials)?;
    
    // New!
    let mut two_fa_code_store = state.two_factor_code_store.write().await;

    // Call `two_fa_code_store.get_code`. If the call fails
    // return a `AuthAPIError::IncorrectCredentials`.
    let code_tuple = two_fa_code_store
                    .get_code(&email)
                    .await
                    .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    // Validate that the `login_attempt_id` and `two_fa_code`
    // in the request body matches values in the `code_tuple`. 
    // If not, return a `AuthAPIError::IncorrectCredentials`.
    if (login_attempt_id, two_fa_code) != code_tuple {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    let cookie = generate_auth_cookie(&email)
        .map_err(|_| AuthAPIError::UnexpectedError)?;
    let updated_jar = jar.add(cookie);

    two_fa_code_store.remove_code(&email).await
        .map_err(|_| AuthAPIError::UnexpectedError)?;
    
    Ok((updated_jar, StatusCode::OK))
}

// implement the Verify2FARequest struct. See the verify-2fa route contract in step 1 for the expected JSON body.
#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Verify2FAResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}*/
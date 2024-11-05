use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar, // New!
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {

    // match email, if there is a parsing error, return AuthAPIError::InvalidCredentials
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };


    let password = match Password::parse(request.password) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let user_store = &state.user_store.read().await;

    // call `user_store.validate_user` and return
    // `AuthAPIError::IncorrectCredentials` if validation fails.
    if user_store.validate_user(email.clone(), password.clone()).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    };

    let user = match user_store.get_user(email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(&user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}


#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

// New!
async fn handle_2fa(
    email: &Email, // New!
    state: &AppState, // New!
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id: LoginAttemptId = LoginAttemptId::default();
    let two_fa_code: TwoFACode = TwoFACode::default(); // New!

    // Store the ID and code in our 2FA code store. Return `AuthAPIError::UnexpectedError` if the operation fails
    let stored_2fa_result= state.
                            two_factor_code_store.
                            write().
                            await.
                            add_code(email.to_owned(), login_attempt_id.clone(), two_fa_code.clone()).await;
    if let Err(_) = stored_2fa_result {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // send 2FA code via the email client. Return `AuthAPIError::UnexpectedError` if the operation fails.

    let email_client = state.email_client.read().await;
    let send_result = email_client.
                        send_email(
                        email,
                            "Subject: 2FA code",
                            two_fa_code.as_ref()
                        ).await;

    if let Err(_) = send_result {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // Return a TwoFactorAuthResponse. The message should be "2FA required".
    // The login attempt ID should be "123456". We will replace this hard-coded login attempt ID soon!
    let two_factor_auth_response = TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
    };

    let updated_jar = jar.add(Cookie::new("login_attempt_id", "123456"));

    (updated_jar, Ok((StatusCode::PARTIAL_CONTENT, Json(LoginResponse::TwoFactorAuth(two_factor_auth_response)))))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };
    let updated_jar = jar.add(auth_cookie);
    (updated_jar, Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))))
}


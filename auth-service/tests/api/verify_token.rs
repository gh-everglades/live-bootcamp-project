use auth_service::utils::{auth::generate_auth_token, constants::JWT_COOKIE_NAME};
use auth_service::domain::Email;
use crate::helpers::{get_random_email, TestApp};




#[tokio::test]
async fn should_return_200_valid_token() {
    // if the JWT token is valid, a 200 HTTP status code should be sent back.
    // Generate a random email and use it to generate a JWT token. Then, send a POST request to the /verify-token route with the token as a JSON object.
    // Assert that a 200 HTTP status code is returned.
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);
    let auth_cookie = response
            .cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");
    let token = auth_cookie.value();
    let verify_body = serde_json::json!({
        "token": token
    });
    let response = app.post_verify_token(&verify_body).await;
    assert_eq!(response.status().as_u16(), 200);

    
}



#[tokio::test]
async fn should_return_401_if_invalid_token() {
    // If the JSON object contains an invalid or incorrect token, a 401 HTTP status code should be returned.
    // Generate a random email and use it to generate a JWT token. Then, send a POST request to the /verify-token route with an invalid or incorrect token as a JSON object.
    // Assert that a 401 HTTP status code is returned.
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);
    let auth_cookie = response
            .cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");
    let token = auth_cookie.value();
    let verify_body = serde_json::json!({
        "token": "invalid_token"
    });
    let response = app.post_verify_token(&verify_body).await;
    assert_eq!(response.status().as_u16(), 401);

}

// If the JSON object is missing or malformed, a 422 HTTP status code should be sent back. 
#[tokio::test]
async fn should_return_422_if_malformed_input() {

    let app = TestApp::new().await;

    let email = Email::parse("test@example.com".to_owned()).unwrap();
    let result = generate_auth_token(&email).unwrap();

    let verify_body = serde_json::json!({
        "token": result
    });
    println!("Token: {}", result);
    let response = app.post_signup(&verify_body).await;
    assert_eq!(response.status().as_u16(), 422);
}
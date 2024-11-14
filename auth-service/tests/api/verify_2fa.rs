use auth_service::{domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME};
use secrecy::{Secret, ExposeSecret};
use wiremock::{matchers::{method, path}, Mock, ResponseTemplate};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email 

    // add more malformed input test cases
    let test_cases = [
        serde_json::json!({
            "loginAttemptId": "123456",
            "2FACode": "999999"
        }),
        serde_json::json!({
            "email": random_email,
            "2FACode": "999999"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await; 
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    

    // add invalid input test cases
    let test_cases = [
        // wrong email format
        serde_json::json!({
            "email": "invalid-email",
            "loginAttemptId": "550e8400-e29b-41d4-a716-446655440000",
            "2FACode": "999999"
        }),
        // wrong 2FACode length
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "550e8400-e29b-41d4-a716-446655440000",
            "2FACode": "123"
        }),
        // wrong 2FACode format
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "550e8400-e29b-41d4-a716-446655440000",
            "2FACode": "123XYZ"
        }),
        // wrong loginAttemptId format
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "550e8400-e29b-",
            "2FACode": "123456"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await; 
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    // Create a user with a strong password
    let response = app
        .post_signup(&serde_json::json!({
            "email": random_email,
            "password": "StrongPassword199$123",
            "requires2FA": true
        }))
       .await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    // Login with the created user
    let response = app
       .post_login(&serde_json::json!({
            "email": random_email,
            "password": "StrongPassword199$123",
            "requires2FA": true
        }))
       .await;

    assert_eq!(response.status().as_u16(), 206);

    // Get the login attempt ID
    let response = response.json::<TwoFactorAuthResponse>().await.unwrap();
    let login_attempt_id = response.login_attempt_id;
    println!("Login attempt ID: {}", login_attempt_id);

    // Verify 2FA code with incorrect code
    let response = app
       .post_verify_2fa(&serde_json::json!({
            "email": random_email,
            "loginAttemptId": login_attempt_id.to_string(),
            "2FACode": "123456"
        }))
       .await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail. 
    
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    // Create a user with a strong password
    let response = app
       .post_signup(&serde_json::json!({
            "email": random_email,
            "password": "StrongPassword199$123",
            "requires2FA": true
        }))
       .await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    // Login with the created user
    let response = app
       .post_login(&serde_json::json!({
            "email": random_email,
            "password": "StrongPassword199$123",
            "requires2FA": true
        }))
       .await;

    assert_eq!(response.status().as_u16(), 206);

    // Get the login attempt ID
    let response = response.json::<TwoFactorAuthResponse>().await.unwrap();
    let login_attempt_id = response.login_attempt_id;
    println!("Login attempt ID: {}", login_attempt_id);
    
    let code_tuple = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let first_token = code_tuple.1.as_ref();

    // Login with the created user again
    let response = app
       .post_login(&serde_json::json!({
            "email": random_email,
            "password": "StrongPassword199$123",
            "requires2FA": true
        }))
       .await;

    assert_eq!(response.status().as_u16(), 206);

    // Get the login attempt ID again
    let response = response.json::<TwoFactorAuthResponse>().await.unwrap();
    let second_login_attempt_id = response.login_attempt_id;
    println!("Second login attempt ID: {}", second_login_attempt_id);

    // Verify 2FA code with the second login request's token
    let response = app
     .post_verify_2fa(&serde_json::json!({
            "email": random_email,
            "loginAttemptId": second_login_attempt_id,
            "2FACode": first_token.expose_secret()
        }))
        .await;
    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    // Make sure to assert the auth cookie gets set
    let mut app = TestApp::new().await;
    let random_email = get_random_email();
    // Create a user with a strong password
    let response = app
       .post_signup(&serde_json::json!({
            "email": random_email,
            "password": "StrongPassword199$123",
            "requires2FA": true
        }))
        .await;
    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;
    
    // Login with the created user
    let response = app
       .post_login(&serde_json::json!({
            "email": random_email,
            "password": "StrongPassword199$123",
            "requires2FA": true
        }))
        .await;
    assert_eq!(response.status().as_u16(), 206);
    
    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let login_attempt_id = response_body.login_attempt_id;

    let code_tuple = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let code = code_tuple.1.as_ref();

    let request_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id,
        "2FACode": code.expose_secret()
    });

    let response = app.post_verify_2fa(&request_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());


    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let login_attempt_id = response_body.login_attempt_id;

    let code_tuple = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let code = code_tuple.1.as_ref();

    let request_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id,
        "2FACode": code.expose_secret()
    });

    let response = app.post_verify_2fa(&request_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response = app.post_verify_2fa(&request_body).await;
    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}
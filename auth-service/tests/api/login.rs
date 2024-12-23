use auth_service::{domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME};
use secrecy::{Secret, ExposeSecret};
use wiremock::{matchers::{method, path}, Mock, ResponseTemplate};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    // Define an expectation for the mock server
    Mock::given(path("/email")) // Expect an HTTP request to the "/email" path
        .and(method("POST")) // Expect the HTTP method to be POST
        .respond_with(ResponseTemplate::new(200)) // Respond with an HTTP 200 OK status
        .expect(1) // Expect this request to be made exactly once
        .mount(&app.email_server) // Mount this expectation on the mock email server
        .await; // Await the asynchronous operation to ensure the mock server is set up before proceeding

    let login_body = serde_json::json!({
        "email": random_email.clone(),
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    // Tassert that `json_body.login_attempt_id` is stored inside `app.two_fa_code_store`
    
    let login_attempt_id = app.two_fa_code_store.
                read().
                await.
                get_code(&Email::parse(Secret::new(random_email)).unwrap()).
                await.
                unwrap().0.as_ref().expose_secret().to_owned();

    assert_eq!(login_attempt_id, json_body.login_attempt_id);
                                    
    app.clean_up().await;
    

}


#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

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
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email 

    // Add more malformed credentials test cases
    let test_cases = [
        serde_json::json!({
            "email": random_email,
            "pass": "weak",
        }),
        serde_json::json!({
            "user": random_email,
            "password": "weak-password",
            "confirm_password": "weak-password",
        }),
        serde_json::json!({
            "e": "invalid-email",
            "password": "weak-password",
        }),
        serde_json::json!({
            "email": random_email,
            "confirm_password": "invalid-confirm-password",
        }),
    ];

    for test_case in test_cases {
        let response = app.post_login(&test_case).await;
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
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message. 
    // The signup route should return a 400 HTTP status code if an invalid input is sent.
    // The input is considered invalid if:
    // - The email is empty or does not contain '@'
    // - The password is less than 8 characters

    // Create an array of invalid inputs. Then, iterate through the array and 
    // make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.
    let mut app = TestApp::new().await;

    let random_email = get_random_email(); 
    let input = [
        serde_json::json!({
            "email": "",
            "password": "password123",
        }),
        serde_json::json!({
            "email": random_email,
            "password": "short",
        }),
        serde_json::json!({
            "email": "email_no_at",
            "password": "StrongPassword199$",
        }),
    ];

    for i in input.iter() {
        let response = app.post_login(i).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", i);
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.     
    let mut app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email 

    let response = app.post_login(&serde_json::json!({
        "email": random_email,
        "password": "StrongPassword199$123",
    })).await;

    app.clean_up().await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for incorrect credentials"
    );

    
}
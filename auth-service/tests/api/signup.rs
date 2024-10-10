use crate::helpers::TestApp;

// TODO: Implement tests for all other routes (signup, login, logout, verify-2fa, and verify-token)
// For now, simply assert that each route returns a 200 HTTP status code.
#[tokio::test]
async fn signup_returns_200() {
    let app = TestApp::new().await;

    let response = app.signup("example@example.com", "password123").await;

    assert_eq!(response.status().as_u16(), 200);
}
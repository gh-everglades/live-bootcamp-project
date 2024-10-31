use auth_service::{utils::constants::test, Application};
use uuid::Uuid;
use auth_service::app_state::{AppState, UserStoreType};
use tokio::sync::RwLock;
use std::sync::Arc;
use auth_service::services::HashmapUserStore;
use reqwest::cookie::Jar;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>, // New!
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store: UserStoreType = Arc::new(RwLock::new(HashmapUserStore::default()));
        let app_state = AppState::new(user_store);

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread. 
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        //let http_client = todo!(); // Create a Reqwest http client instance
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        // Create new `TestApp` instance and return it

        Self {
            address,
            cookie_jar,
            http_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    // Implement helper functions for all other routes (signup, login, logout, verify-2fa, and verify-token)
    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }


    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.http_client
           .post(&format!("{}/logout", &self.address))
           .send()
           .await
           .expect("Failed to execute request.")
    }

    pub async fn verify_2fa(&self, code: &str) -> reqwest::Response {
        self.http_client
           .post(&format!("{}/verify-2fa", &self.address))
           .json(&serde_json::json!({ "code": code }))
           .send()
           .await
           .expect("Failed to execute request.")
    }

    pub async fn verify_token(&self, token: &str) -> reqwest::Response {
        self.http_client
           .post(&format!("{}/verify-token", &self.address))
           .json(&serde_json::json!({ "token": token }))
           .send()
           .await
           .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
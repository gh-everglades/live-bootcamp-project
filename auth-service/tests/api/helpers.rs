use auth_service::Application;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread. 
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = todo!(); // Create a Reqwest http client instance

        // Create new `TestApp` instance and return it
        TestApp { address, http_client }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    // TODO: Implement helper functions for all other routes (signup, login, logout, verify-2fa, and verify-token)
    pub async fn signup(&self, email: &str, password: &str) -> reqwest::Response {
        self.http_client
           .post(&format!("{}/signup", &self.address))
           .json(&serde_json::json!({ "email": email, "password": password }))
           .send()
           .await
           .expect("Failed to execute request.")
    }

    pub async fn login(&self, email: &str, password: &str) -> reqwest::Response {
        self.http_client
           .post(&format!("{}/login", &self.address))
           .json(&serde_json::json!({ "email": email, "password": password }))
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
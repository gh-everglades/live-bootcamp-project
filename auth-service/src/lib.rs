use std::error::Error;

use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};

use tower_http::{cors::CorsLayer, services::ServeDir};
use app_state::AppState;


pub mod routes;
pub mod domain;
pub mod services;
pub mod utils;


// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Allow the app service(running on our local machine and in production) to call the auth service
        let allowed_origins = [
            "http://localhost:3000".parse()?,
            "http://localhost:8000".parse()?,
            "http://147.182.215.185:3000".parse()?,
            "http://147.182.215.185:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            // Allow GET and POST requests
            .allow_methods([Method::GET, Method::POST])
            // Allow cookies to be included in requests
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token))
            .with_state(app_state)
            .layer(cors); // Add CORS config to our Axum router

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

pub mod app_state {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::domain::{BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};

    // Using a type alias to improve readability!
    pub type UserStoreType = Arc<RwLock<dyn UserStore + Send + Sync>>;
    pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;
    pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>;
    pub type EmailClientType = Arc<RwLock<dyn EmailClient + Send + Sync>>;


    #[derive(Clone)]
    pub struct AppState {
        pub user_store: UserStoreType,
        pub banned_token_store: BannedTokenStoreType,
        pub two_factor_code_store: TwoFACodeStoreType,
        pub email_client: EmailClientType,
    }

    impl AppState {
        pub fn new(
            user_store: UserStoreType, 
            banned_token_store: BannedTokenStoreType,
            two_factor_code_store: TwoFACodeStoreType,
            email_client: EmailClientType,
        ) -> Self {
            Self { 
                user_store,
                banned_token_store,
                two_factor_code_store,
                email_client,
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "Incorrect credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            },
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}
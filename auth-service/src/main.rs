use std::sync::Arc;
use auth_service::{
    app_state::{AppState, EmailClientType, TwoFACodeStoreType, UserStoreType}, domain::mock_email_client::MockEmailClient, get_postgres_pool, services::{HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore}, utils::constants::{env::DATABASE_URL, prod}, Application
};
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    // We will use this PostgreSQL pool in the next task! 
    let pg_pool = configure_postgresql().await;

    let user_store: UserStoreType = Arc::new(RwLock::new(HashmapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_factor_code_store: TwoFACodeStoreType  = Arc::new(RwLock::new(HashmapTwoFACodeStore::default())); 
    let email_client: EmailClientType = Arc::new(RwLock::new(MockEmailClient));
    let app_state = AppState::new(user_store, banned_token_store, two_factor_code_store, email_client);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database! 
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

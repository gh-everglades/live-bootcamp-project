use std::sync::Arc;
use auth_service::{
    app_state::{AppState, EmailClientType, TwoFACodeStoreType, UserStoreType}, domain::mock_email_client::MockEmailClient, services::{HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore}, utils::constants::prod, Application
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
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

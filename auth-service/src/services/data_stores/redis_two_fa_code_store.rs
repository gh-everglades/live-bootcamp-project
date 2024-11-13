use std::sync::Arc;

use redis::{Commands, Connection};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use color_eyre::eyre::Context;


use crate::domain::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError,Email};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "2FA Store Add Code", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        // 1. Create a new key using the get_key helper function.
        // 2. Create a TwoFATuple instance.
        // 3. Use serde_json::to_string to serialize the TwoFATuple instance into a JSON string. 
        // Return TwoFACodeStoreError::UnexpectedError if serialization fails.
        // 4. Call the set_ex command on the Redis connection to set a new key/value pair with an expiration time (TTL). 
        // The value should be the serialized 2FA tuple.
        // The expiration time should be set to TEN_MINUTES_IN_SECONDS.
        // Return TwoFACodeStoreError::UnexpectedError if casting fails or the call to set_ex fails.

        let key = get_key(&email);

        let data = TwoFATuple(
            login_attempt_id.as_ref().expose_secret().to_owned(),
            code.as_ref().expose_secret().to_owned(),
        );
        let serialized_data = serde_json::to_string(&data)
            .wrap_err("failed to serialize 2FA tuple") // New!
            .map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, serialized_data, TEN_MINUTES_IN_SECONDS)
            .wrap_err("failed to set 2FA code in Redis") // New! 
            .map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

        Ok(())
    }

    #[tracing::instrument(name = "2FA Store Remove Code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        // 1. Create a new key using the get_key helper function.
        // 2. Call the del command on the Redis connection to delete the 2FA code entry. 
        // Return TwoFACodeStoreError::UnexpectedError if the operation fails.

        let key = get_key(email);

        let _: () = self
            .conn
            .write()
            .await
            .del(&key)
            .wrap_err("failed to delete 2FA code from Redis") // New!
            .map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

        Ok(())
    }

    #[tracing::instrument(name = "2FA Store Get Code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        // 1. Create a new key using the get_key helper function.
        // 2. Call the get command on the Redis connection to get the value stored for the key. 
        // Return TwoFACodeStoreError::LoginAttemptIdNotFound if the operation fails.
        // If the operation succeeds, call serde_json::from_str to parse the JSON string into a TwoFATuple. 
        // Then, parse the login attempt ID string and 2FA code string into a LoginAttemptId and TwoFACode type respectively.
        // Return TwoFACodeStoreError::UnexpectedError if parsing fails.

        let key = get_key(email);

        match self.conn.write().await.get::<_, String>(&key) {
            Ok(value) => {
                let data: TwoFATuple = serde_json::from_str(&value)
                    .wrap_err("failed to deserialize 2FA tuple") // New!
                    .map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

                let login_attempt_id =
                    LoginAttemptId::parse(Secret::new(data.0)).map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

                let email_code =
                    TwoFACode::parse(Secret::new(data.1)).map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

                Ok((login_attempt_id, email_code))
            }
            Err(_) => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

#[tracing::instrument(name = "2FA Store Get Key", skip_all)]
fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.expose_secret())
}
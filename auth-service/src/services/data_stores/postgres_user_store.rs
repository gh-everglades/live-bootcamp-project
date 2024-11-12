use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{domain::{
    Email, Password, User, UserStore, UserStoreError
}, utils::constants::PG_TABLE_NAME};

use color_eyre::eyre::{eyre, Context, Result};

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct Users {
    pub email: String,
    pub password_hash: String,
    pub requires_2fa: bool,
}

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    // Implement all required methods. Note that you will need to make SQL queries against our PostgreSQL instance inside these methods.
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(user.password.as_ref().to_owned())
            .await
            .map_err(UserStoreError::UnexpectedError)?; // Updated!

        sqlx::query!(
            r#"
            INSERT INTO users (email, password_hash, requires_2fa)
            VALUES ($1, $2, $3)
            "#,
            user.email.as_ref(),
            &password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?; // Updated!

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: Email) -> Result<User, UserStoreError> {
        sqlx::query!(
            r#"
            SELECT email, password_hash, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .map(|row| {
            Ok(User {
                email: Email::parse(row.email)
                    .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?, // Updated!
                password: Password::parse(row.password_hash)
                    .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?, // Updated!
                requires_2fa: row.requires_2fa,
            })
        })
        .ok_or(UserStoreError::UserNotFound)?
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)] // New!
    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError> {
        let sql = format!("select * from {} where email = $1", PG_TABLE_NAME);
        let query = sqlx::query_as::<_, Users>(&sql);
        let data = match query.bind(email.as_ref()).fetch_one(&self.pool).await {
            Ok(u) => u,
            Err(e) => match e {
                sqlx::Error::RowNotFound => return Err(UserStoreError::UserNotFound),
                _ => return Err(UserStoreError::UnexpectedError(eyre!(e))),
            }
        };

        let pwd_hash = data.password_hash;
        let pwd = password.as_ref().to_string();
        
        verify_password_hash(pwd_hash, pwd).await
                .map_err(|_| UserStoreError::InvalidCredentials)?;
            
        Ok(())
    }
}

// Helper function to verify if a given password matches an expected hash
// Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking. Note that you
// will need to update the input parameters to be String types instead of &str
#[tracing::instrument(name = "Verify password hash", skip_all)] // New!
pub async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<()> {
    // This line retrieves the current span from the tracing context. 
    // The span represents the execution context for the compute_password_hash function.
    let current_span: tracing::Span = tracing::Span::current(); // New!
    let result = tokio::task::spawn_blocking(move || {
        // This code block ensures that the operations within the closure are executed within the context of the current span. 
        // This is especially useful for tracing operations that are performed in a different thread or task, such as within tokio::task::spawn_blocking.
        current_span.in_scope(|| { // New!
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(&expected_password_hash)?;

            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                .wrap_err("failed to verify password hash")
        })
    })
    .await;

    result?
}

// Helper function to hash passwords before persisting them in the database.
// Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking. Note that you
// will need to update the input parameters to be String types instead of &str
#[tracing::instrument(name = "Computing password hash", skip_all)] //New!
async fn compute_password_hash(password: String) -> Result<String> {
    // This line retrieves the current span from the tracing context. 
    // The span represents the execution context for the compute_password_hash function.
    let current_span: tracing::Span = tracing::Span::current(); // New!

    let result = tokio::task::spawn_blocking(move || {
        // This code block ensures that the operations within the closure are executed within the context of the current span. 
        // This is especially useful for tracing operations that are performed in a different thread or task, such as within tokio::task::spawn_blocking.
        current_span.in_scope(|| { // New!
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            // Ok(password_hash)
            Err(eyre!("oh no!")) // New!
        })
    })
    .await;

    result?
}


/*mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_get_user() {
        let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");
    
        let mut store = PostgresUserStore::new(pg_pool);
        
        let random_email = format!("{}@example.com", Uuid::new_v4());

        let email = Email::parse(random_email.to_string()).unwrap();
        let password = Password::parse("password123".to_string()).unwrap();
        let user = User::new(email.clone(), password.clone(), true);

        store.add_user(user.clone()).await.unwrap();
        let user_from_db = store.get_user(email).await.unwrap();

        assert_eq!(user_from_db.email, user.email);
        assert!(verify_password_hash(user_from_db.password.as_ref().to_string(), password.as_ref().to_string()).await.is_ok());
        assert_eq!(user_from_db.requires_2fa, user.requires_2fa);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

        let mut store = PostgresUserStore::new(pg_pool);

        let random_email = format!("{}@example.com", Uuid::new_v4());
        let email = Email::parse(random_email.to_string()).unwrap();
        let password = Password::parse("password123".to_string()).unwrap();
        let user = User::new(email.clone(), password.clone(), true);
        store.add_user(user.clone()).await.unwrap();
        assert!(store.validate_user(email.clone(), password.clone()).await.is_ok());
        
    }
}*/
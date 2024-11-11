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
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        
        let password_hash = compute_password_hash(user.password.as_ref().to_string())
            .await.map_err(|_| UserStoreError::InvalidCredentials)?;
        

        let sql = format!("insert into {} (email, password_hash, requires_2fa) values ($1, $2, $3)", PG_TABLE_NAME);
        let query = sqlx::query(&sql);
        query
            .bind(user.email.as_ref())
            .bind(password_hash)
            .bind(user.requires_2fa)
            .execute(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(())
    }
    async fn get_user(&self, email: Email) -> Result<User, UserStoreError> {
        let sql = format!("select * from {} where email = $1", PG_TABLE_NAME);
        let query = sqlx::query_as::<_, Users>(&sql);
        let data = match query.bind(email.as_ref()).fetch_one(&self.pool).await {
            Ok(u) => u,
            Err(e) => match e {
                sqlx::Error::RowNotFound => return Err(UserStoreError::UserNotFound),
                _ => return Err(UserStoreError::UnexpectedError),
            }
        };

        let email = Email::parse(data.email)
            .map_err(|_| UserStoreError::InvalidCredentials)?;
        let password = Password::parse(data.password_hash)
            .map_err(|_| UserStoreError::InvalidCredentials)?;
        let user = User::new(email, password, data.requires_2fa);

        Ok(user)
    }
    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError> {
        let sql = format!("select * from {} where email = $1", PG_TABLE_NAME);
        let query = sqlx::query_as::<_, Users>(&sql);
        let data = match query.bind(email.as_ref()).fetch_one(&self.pool).await {
            Ok(u) => u,
            Err(e) => match e {
                sqlx::Error::RowNotFound => return Err(UserStoreError::UserNotFound),
                _ => return Err(UserStoreError::UnexpectedError),
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
pub async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let res = tokio::task::spawn_blocking(move || {
        let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&expected_password_hash)?;

        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_password_hash)
            .map_err(|e| e.into())
    })
    .await;

    res?
}

// Helper function to hash passwords before persisting them in the database.
// Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking. Note that you
// will need to update the input parameters to be String types instead of &str
pub async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    let res = tokio::task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None)?,
        )
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

        Ok(password_hash)
    })
    .await;

    res?

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
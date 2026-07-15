use async_trait::async_trait;
use password_auth::{generate_hash, verify_password};
use tokio::task;

#[async_trait]
pub trait PasswordHasher: std::fmt::Debug + Send + Sync {
    async fn genereate_hash(&self, password: String) -> String;
    async fn verify_password(&self, password: String, hash: String) -> bool;
}

#[derive(Debug, Clone)]
pub struct DefaultPasswordHasher;

#[async_trait]
impl PasswordHasher for DefaultPasswordHasher {
    async fn genereate_hash(&self, password: String) -> String {
        task::spawn_blocking(move || generate_hash(password))
            .await
            .expect("Join error")
    }

    async fn verify_password(&self, password: String, hash: String) -> bool {
        task::spawn_blocking(move || verify_password(password, hash.as_str()).is_ok())
            .await
            .expect("Join error")
    }
}

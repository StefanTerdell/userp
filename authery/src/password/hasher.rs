use password_auth::{generate_hash, verify_password};
use std::{future::Future, pin::Pin};
use tokio::task;

pub trait PasswordHasher: std::fmt::Debug + Send + Sync {
    fn generate_hash(&self, password: String) -> Pin<Box<dyn Future<Output = String> + Send>>;
    fn verify_password(
        &self,
        password: String,
        hash: String,
    ) -> Pin<Box<dyn Future<Output = bool> + Send>>;
}

#[derive(Debug, Clone)]
pub struct DefaultPasswordHasher;

impl PasswordHasher for DefaultPasswordHasher {
    fn generate_hash(&self, password: String) -> Pin<Box<dyn Future<Output = String> + Send>> {
        Box::pin(async move {
            task::spawn_blocking(move || generate_hash(password))
                .await
                .expect("Join error")
        })
    }

    fn verify_password(
        &self,
        password: String,
        hash: String,
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        Box::pin(async move {
            task::spawn_blocking(move || verify_password(password, hash.as_str()).is_ok())
                .await
                .expect("Join error")
        })
    }
}

use crate::password;
use axum::async_trait;
use serde::Deserialize;
use userp::{uuid::Uuid, LoginMethod, LoginSession, User};

#[derive(Deserialize)]
pub struct SigninForm {
    pub email_address: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct MyUser {
    pub id: Uuid,
    pub password_hash: Option<String>,
    pub email: String,
}

#[async_trait]
impl User for MyUser {
    fn get_allow_password_login(&self) -> bool {
        self.password_hash.is_some()
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl MyUser {
    pub async fn validate_password(&self, password: &str) -> bool {
        if let Some(hash) = self.password_hash.as_ref() {
            password::verify(password.to_string(), hash.clone()).await
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct MyLoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
}

impl LoginSession for MyLoginSession {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_method(&self) -> &LoginMethod {
        &self.method
    }
}

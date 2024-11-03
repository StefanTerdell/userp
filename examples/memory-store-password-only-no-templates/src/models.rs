use serde::Deserialize;
use userp::{prelude::*, reexports::uuid::Uuid};

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

impl User for MyUser {
    fn get_password_hash(&self) -> Option<String> {
        self.password_hash.clone()
    }

    fn get_id(&self) -> Uuid {
        self.id
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

    fn get_method(&self) -> LoginMethod {
        self.method.clone()
    }
}

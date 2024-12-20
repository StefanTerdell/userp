use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use userp::{prelude::*, reexports::uuid::Uuid};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyUser {
    pub id: Uuid,
    pub password_hash: Option<String>,
    pub emails: Vec<MyUserEmail>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyUserEmail {
    pub user_id: Uuid,
    pub email: String,
    pub verified: bool,
    pub allow_link_login: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyLoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MyEmailChallenge {
    pub address: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[allow(unused)]
pub struct MyOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

#[cfg(feature = "ssr")]
pub mod ssr {
    use super::*;
    use chrono::{DateTime, Utc};
    use userp::reexports::uuid::Uuid;

    impl User for MyUser {
        fn get_password_hash(&self) -> Option<String> {
            self.password_hash.clone()
        }

        fn get_id(&self) -> Uuid {
            self.id
        }
    }

    impl UserEmail for MyUserEmail {
        fn get_user_id(&self) -> Uuid {
            self.user_id
        }

        fn get_address(&self) -> &str {
            self.email.as_str()
        }

        fn get_verified(&self) -> bool {
            self.verified
        }

        fn get_allow_link_login(&self) -> bool {
            self.allow_link_login
        }
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

    impl EmailChallenge for MyEmailChallenge {
        fn get_address(&self) -> &str {
            &self.address
        }

        fn get_code(&self) -> &str {
            &self.code
        }

        fn get_next(&self) -> &Option<String> {
            &self.next
        }

        fn get_expires(&self) -> DateTime<Utc> {
            self.expires
        }
    }
    impl OAuthToken for MyOAuthToken {
        fn get_id(&self) -> Uuid {
            self.id
        }

        fn get_user_id(&self) -> Uuid {
            self.user_id
        }

        fn get_provider_name(&self) -> &str {
            self.provider_name.as_str()
        }

        fn get_refresh_token(&self) -> &Option<String> {
            &self.refresh_token
        }
    }
}

//! The app's own entity types. Authery only sees them through its traits -
//! extra columns, different names or newtype ids would all be fine.

#[allow(unused_imports)]
use authery::{
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        uuid::Uuid,
    },
};
use sqlx::types::Json;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PgUser {
    pub id: Uuid,
    pub password_hash: Option<String>,
}

impl User for PgUser {
    type Id = Uuid;

    fn get_id(&self) -> Uuid {
        self.id
    }

    #[cfg(feature = "password")]
    fn get_password_hash(&self) -> Option<String> {
        self.password_hash.clone()
    }
}

#[cfg(feature = "email")]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PgUserEmail {
    pub user_id: Uuid,
    pub address: String,
    pub verified: bool,
    pub allow_link_login: bool,
}

#[cfg(feature = "email")]
impl UserEmail for PgUserEmail {
    type UserId = Uuid;

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_address(&self) -> &str {
        &self.address
    }

    fn get_verified(&self) -> bool {
        self.verified
    }

    fn get_allow_link_login(&self) -> bool {
        self.allow_link_login
    }
}

#[cfg(feature = "sms")]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PgUserPhone {
    pub user_id: Uuid,
    pub number: String,
    pub verified: bool,
    pub allow_login: bool,
}

#[cfg(feature = "sms")]
impl UserPhone for PgUserPhone {
    type UserId = Uuid;

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_number(&self) -> &str {
        &self.number
    }

    fn get_verified(&self) -> bool {
        self.verified
    }

    fn get_allow_login(&self) -> bool {
        self.allow_login
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PgSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: Json<LoginMethod>,
    pub expires: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl LoginSession for PgSession {
    type Id = Uuid;
    type UserId = Uuid;

    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_method(&self) -> LoginMethod {
        self.method.0.clone()
    }

    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn get_last_seen(&self) -> Option<DateTime<Utc>> {
        Some(self.last_seen)
    }
}

#[cfg(any(feature = "email", feature = "sms"))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PgChallenge {
    pub code: String,
    pub address: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

#[cfg(any(feature = "email", feature = "sms"))]
impl EmailChallenge for PgChallenge {
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

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(unused)]
pub struct PgOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

#[cfg(feature = "oauth")]
impl OAuthToken for PgOAuthToken {
    type Id = Uuid;
    type UserId = Uuid;

    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_provider_name(&self) -> &str {
        &self.provider_name
    }

    fn get_refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }
}

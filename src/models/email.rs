use crate::models::Id;
use chrono::{DateTime, Utc};

#[cfg(feature = "email")]
pub trait UserEmail: Send + Sync {
    type UserId: Id;

    fn get_user_id(&self) -> Self::UserId;
    fn get_address(&self) -> &str;
    fn get_verified(&self) -> bool;
    fn get_allow_link_login(&self) -> bool;
    /// When the address was verified, for the account page.
    fn get_verified_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        None
    }
}

pub trait EmailChallenge: Send + Sync {
    fn get_address(&self) -> &str;
    fn get_code(&self) -> &str;
    fn get_next(&self) -> &Option<String>;
    fn get_expires(&self) -> DateTime<Utc>;
}

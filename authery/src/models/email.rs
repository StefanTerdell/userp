use chrono::{DateTime, Utc};
use uuid::Uuid;

pub trait UserEmail: Send + Sync {
    fn get_user_id(&self) -> Uuid;
    fn get_address(&self) -> &str;
    fn get_verified(&self) -> bool;
    fn get_allow_link_login(&self) -> bool;
}

pub trait EmailChallenge: Send + Sync {
    fn get_address(&self) -> &str;
    fn get_code(&self) -> &str;
    fn get_next(&self) -> &Option<String>;
    fn get_expires(&self) -> DateTime<Utc>;
}

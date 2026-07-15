use crate::models::Id;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Clone)]
pub struct UnmatchedOAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub provider_name: String,
    pub provider_user_id: String,
    pub provider_user_raw: Value,
}

pub trait OAuthToken: Send + Sync {
    type Id: Id;
    type UserId: Id;

    fn get_id(&self) -> Self::Id;
    fn get_user_id(&self) -> Self::UserId;
    fn get_provider_name(&self) -> &str;
    fn get_refresh_token(&self) -> &Option<String>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthProviderUser {
    pub id: String,
    pub raw: Value,
}

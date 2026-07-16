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
    /// For OIDC providers this holds the VALIDATED id_token claims; for plain
    /// OAuth providers, the userinfo response.
    pub provider_user_raw: Value,
    /// The app-chosen context string this flow was started with (see
    /// [`crate::oauth::OAuthProviderResolver`]), `None` for flows using the
    /// statically configured providers. The store receives it verbatim at
    /// user/token creation - the hook where app-level tenant/org logic (e.g.
    /// membership upserts from `provider_user_raw` claims) belongs.
    pub context: Option<String>,
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

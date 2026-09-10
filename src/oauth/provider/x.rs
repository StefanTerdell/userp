use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct XOAuthProvider;

impl XOAuthProvider {
    /// X (formerly Twitter), OAuth 2.0 with PKCE (always sent by authery).
    /// `offline.access` is included so refresh tokens are issued.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "x",
            "X",
            client_id,
            client_secret,
            "https://x.com/i/oauth2/authorize",
            "https://api.x.com/2/oauth2/token",
            // users.read only works in combination with tweet.read.
            &["users.read", "tweet.read", "offline.access"],
            |access_token, _| async move {
                let raw = reqwest::Client::new()
                    .get("https://api.x.com/2/users/me")
                    .bearer_auth(access_token)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Value>()
                    .await?;

                let id = raw["data"]["id"]
                    .as_str()
                    .context("Missing 'data.id' in response")?
                    .to_string();

                Ok(OAuthProviderUser { id, raw })
            },
        )
        .expect("Built in providers should work")
    }
}

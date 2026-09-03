use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct SlackOAuthProvider;

impl SlackOAuthProvider {
    /// Sign in with Slack (OpenID Connect endpoints).
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "slack",
            "Slack",
            client_id,
            client_secret,
            "https://slack.com/openid/connect/authorize",
            "https://slack.com/api/openid.connect.token",
            &["openid", "profile", "email"],
            |access_token, _| async move {
                let raw = reqwest::Client::new()
                    .get("https://slack.com/api/openid.connect.userInfo")
                    .bearer_auth(access_token)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Value>()
                    .await?;

                let id = raw["sub"]
                    .as_str()
                    .context("Missing 'sub' in response")?
                    .to_string();

                Ok(OAuthProviderUser { id, raw })
            },
        )
        .expect("Built in providers should work")
    }
}

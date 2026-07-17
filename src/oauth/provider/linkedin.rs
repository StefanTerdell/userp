use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct LinkedInOAuthProvider;

impl LinkedInOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "linkedin",
            "LinkedIn",
            client_id,
            client_secret,
            "https://www.linkedin.com/oauth/v2/authorization",
            "https://www.linkedin.com/oauth/v2/accessToken",
            &["openid", "profile", "email"],
            |access_token, _| async move {
                let raw = reqwest::Client::new()
                    .get("https://api.linkedin.com/v2/userinfo")
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

use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct DiscordOAuthProvider;

impl DiscordOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "discord",
            "Discord",
            client_id,
            client_secret,
            "https://discord.com/oauth2/authorize",
            "https://discord.com/api/oauth2/token",
            &["identify", "email"],
            |access_token, _| async move {
                let raw = reqwest::Client::new()
                    .get("https://discord.com/api/users/@me")
                    .bearer_auth(access_token)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Value>()
                    .await?;

                let id = raw["id"]
                    .as_str()
                    .context("Missing 'id' in response")?
                    .to_string();

                Ok(OAuthProviderUser { id, raw })
            },
        )
        .expect("Built in providers should work")
    }
}

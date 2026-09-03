use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct TwitchOAuthProvider;

impl TwitchOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        let client_id = client_id.into();
        // Helix requires the app's Client-Id alongside the bearer token.
        let header_client_id = client_id.clone();

        OAuthCustomProvider::new_with_callback(
            "twitch",
            "Twitch",
            client_id,
            client_secret,
            "https://id.twitch.tv/oauth2/authorize",
            "https://id.twitch.tv/oauth2/token",
            &["user:read:email"],
            move |access_token, _| {
                let header_client_id = header_client_id.clone();

                async move {
                    let raw = reqwest::Client::new()
                        .get("https://api.twitch.tv/helix/users")
                        .header("Client-Id", header_client_id)
                        .bearer_auth(access_token)
                        .send()
                        .await?
                        .error_for_status()?
                        .json::<Value>()
                        .await?;

                    let id = raw["data"][0]["id"]
                        .as_str()
                        .context("Missing 'data[0].id' in response")?
                        .to_string();

                    Ok(OAuthProviderUser { id, raw })
                }
            },
        )
        .expect("Built in providers should work")
    }
}

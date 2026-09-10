use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct SpotifyOAuthProvider;

impl SpotifyOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "spotify",
            "Spotify",
            client_id,
            client_secret,
            "https://accounts.spotify.com/authorize",
            "https://accounts.spotify.com/api/token",
            &["user-read-email"],
            |access_token, _| async move {
                let client = reqwest::Client::new();

                let raw = client
                    .get("https://api.spotify.com/v1/me")
                    .header("Accept", "application/json")
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

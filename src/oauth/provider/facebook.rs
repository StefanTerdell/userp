use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct FacebookOAuthProvider;

impl FacebookOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "facebook",
            "Facebook",
            client_id,
            client_secret,
            "https://www.facebook.com/v19.0/dialog/oauth",
            "https://graph.facebook.com/v19.0/oauth/access_token",
            &["public_profile", "email"],
            |access_token, _| async move {
                let raw = reqwest::Client::new()
                    .get("https://graph.facebook.com/me?fields=id,name,email")
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

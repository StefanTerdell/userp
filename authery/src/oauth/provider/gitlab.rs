use super::{custom::OAuthCustomProvider, oidc::OAuthOidcProvider};
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct GitLabOAuthProvider;

impl GitLabOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "gitlab",
            "GitLab",
            client_id,
            client_secret,
            "https://gitlab.com/oauth/authorize",
            "https://gitlab.com/oauth/token",
            &["openid"],
            |access_token, _| async move {
                let client = reqwest::Client::new();

                let raw = client
                    .get("https://gitlab.com/oauth/userinfo")
                    .header("Accept", "application/json")
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

    /// ⚠️ Warning: JWT token signature is not checked yet.
    pub fn new_oidc_unverified(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthOidcProvider {
        OAuthOidcProvider::new(
            "gitlab",
            "GitLab OIDC",
            client_id,
            client_secret,
            "https://gitlab.com/oauth/authorize",
            "https://gitlab.com/oauth/token",
            &["openid"],
        )
        .expect("Built in providers should work")
    }
}

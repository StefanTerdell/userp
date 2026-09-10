use super::custom::OAuthCustomProvider;
use crate::models::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct MicrosoftOAuthProvider;

impl MicrosoftOAuthProvider {
    /// Microsoft (Entra ID + personal accounts) via the `common` endpoint and
    /// the Graph API. For single-tenant setups with id_token validation, use
    /// [`crate::oauth::provider::oidc::OAuthOidcProvider`] with your tenant's
    /// issuer instead.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "microsoft",
            "Microsoft",
            client_id,
            client_secret,
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            &["User.Read"],
            |access_token, _| async move {
                let raw = reqwest::Client::new()
                    .get("https://graph.microsoft.com/v1.0/me")
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

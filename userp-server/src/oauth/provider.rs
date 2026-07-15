pub mod custom;
pub mod github;
pub mod gitlab;
pub mod google;
pub mod oidc;
pub mod spotify;

use crate::models::oauth::UnmatchedOAuthToken;
use async_trait::async_trait;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope};
use url::Url;
use userp_client::models::Allow;

pub type ExchangeResult = anyhow::Result<UnmatchedOAuthToken>;

#[async_trait]
pub trait OAuthProvider: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    fn display_name(&self) -> &str {
        self.name()
    }

    fn allow_signup(&self) -> Option<Allow>;
    fn allow_login(&self) -> Option<Allow>;
    fn allow_linking(&self) -> Option<bool>;

    fn scopes(&self) -> &[Scope];

    fn get_authorization_url_and_state(
        &self,
        base_redirect_url: &RedirectUrl,
        scopes: &[Scope],
    ) -> (Url, CsrfToken, PkceCodeVerifier);

    async fn exchange_authorization_code(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        code: &AuthorizationCode,
        pkce_verifier: Option<PkceCodeVerifier>,
    ) -> ExchangeResult;

    async fn exchange_refresh_token(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        refresh_token: &RefreshToken,
    ) -> ExchangeResult;
}

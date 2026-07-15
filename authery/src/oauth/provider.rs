pub mod custom;
pub mod github;
pub mod gitlab;
pub mod google;
pub mod oidc;
pub mod spotify;

use crate::models::oauth::UnmatchedOAuthToken;
use crate::models::Allow;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope};
use std::{future::Future, pin::Pin};
use url::Url;

pub type ExchangeResult = anyhow::Result<UnmatchedOAuthToken>;

/// A boxed future resolving to an [`ExchangeResult`], keeping the trait
/// object-safe without `async_trait`
pub type ExchangeFuture<'a> = Pin<Box<dyn Future<Output = ExchangeResult> + Send + 'a>>;

pub trait OAuthProvider: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    fn display_name(&self) -> &str {
        self.name()
    }

    fn allow_signup(&self) -> Option<Allow>;
    fn allow_login(&self) -> Option<Allow>;
    fn allow_linking(&self) -> Option<bool>;

    fn scopes(&self) -> &[Scope];

    /// Build the authorization URL. Returns the URL, the CSRF state, the PKCE
    /// verifier, and - for OIDC providers - a nonce to be stored and later
    /// checked against the returned id_token. Non-OIDC providers return `None`.
    fn get_authorization_url_and_state(
        &self,
        base_redirect_url: &RedirectUrl,
        scopes: &[Scope],
    ) -> (Url, CsrfToken, PkceCodeVerifier, Option<String>);

    /// Exchange the authorization code for tokens. `nonce` is the value returned
    /// from [`Self::get_authorization_url_and_state`], round-tripped through the
    /// state cookie, used to validate the OIDC id_token.
    fn exchange_authorization_code<'a>(
        &'a self,
        provider_name: &'a str,
        redirect_url: &'a RedirectUrl,
        code: &'a AuthorizationCode,
        pkce_verifier: Option<PkceCodeVerifier>,
        nonce: Option<String>,
    ) -> ExchangeFuture<'a>;

    fn exchange_refresh_token<'a>(
        &'a self,
        provider_name: &'a str,
        redirect_url: &'a RedirectUrl,
        refresh_token: &'a RefreshToken,
    ) -> ExchangeFuture<'a>;
}

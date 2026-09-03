use super::{OAuthInitError, OAuthSignCallbackError, provider::OAuthProvider};
use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, Intent},
    store::AutheryStore,
};
use std::sync::Arc;
use url::Url;

pub type OAuthLoginInitError = OAuthInitError;
pub type OAuthLoginCallbackError<StoreError> = OAuthSignCallbackError<StoreError>;

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// The providers offered for login under the current policies.
    pub fn oauth_login_providers(&self) -> Vec<&Arc<dyn OAuthProvider>> {
        self.oauth_sign_providers(Intent::LogIn)
    }

    pub async fn oauth_login_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthLoginInitError> {
        self.oauth_sign_init(Intent::LogIn, provider_name, None, next)
            .await
    }

    /// Begin a login through a dynamically resolved provider. `context` is an
    /// opaque, app-chosen string (e.g. a tenant or org id) handed to the
    /// configured [`crate::oauth::OAuthProviderResolver`] here and again at
    /// the callback; the store receives it on the resulting token as
    /// [`crate::models::oauth::UnmatchedOAuthToken::context`].
    pub async fn oauth_login_init_with_context(
        self,
        context: String,
        provider_name: &str,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthLoginInitError> {
        self.oauth_sign_init(
            Intent::LogIn,
            provider_name.to_string(),
            Some(context),
            next,
        )
        .await
    }
}

use super::{OAuthInitError, OAuthSignCallbackError, provider::OAuthProvider};
use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, Intent},
    store::AutheryStore,
};
use std::sync::Arc;
use url::Url;

pub type OAuthSignupInitError = OAuthInitError;
pub type OAuthSignupCallbackError<StoreError> = OAuthSignCallbackError<StoreError>;

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// The providers offered for signup under the current policies.
    pub fn oauth_signup_providers(&self) -> Vec<&Arc<dyn OAuthProvider>> {
        self.oauth_sign_providers(Intent::SignUp)
    }

    pub async fn oauth_signup_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthSignupInitError> {
        self.oauth_sign_init(Intent::SignUp, provider_name, None, next)
            .await
    }

    /// Begin a signup through a dynamically resolved provider. See
    /// [`CoreAuthery::oauth_login_init_with_context`].
    pub async fn oauth_signup_init_with_context(
        self,
        context: String,
        provider_name: &str,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthSignupInitError> {
        self.oauth_sign_init(
            Intent::SignUp,
            provider_name.to_string(),
            Some(context),
            next,
        )
        .await
    }
}

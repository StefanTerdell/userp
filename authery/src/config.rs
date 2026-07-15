#[cfg(feature = "email")]
use crate::email::EmailConfig;
#[cfg(feature = "oauth")]
use crate::oauth::OAuthConfig;
#[cfg(feature = "pages")]
use crate::pages::{AskamaPages, Pages};
#[cfg(feature = "password")]
use crate::password::PasswordConfig;
use crate::{models::Allow, routes::Routes};
#[cfg(feature = "pages")]
use std::sync::Arc;

/// The minimum length, in bytes, of the cookie-encryption key. `axum-extra`'s
/// `Key` panics below this, so we reject short keys up front instead.
pub const MIN_KEY_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum AutheryConfigError {
    #[error("The cookie key must be at least {MIN_KEY_LEN} bytes, got {0}")]
    KeyTooShort(usize),
}

#[derive(Clone)]
pub struct AutheryConfig {
    pub key: String,
    pub allow_signup: Allow,
    pub allow_login: Allow,
    pub https_only: bool,
    pub routes: Routes<String>,
    #[cfg(feature = "password")]
    pub pass: PasswordConfig,
    #[cfg(feature = "email")]
    pub email: EmailConfig,
    #[cfg(feature = "oauth")]
    pub oauth: OAuthConfig,
    /// The renderer for the built-in pages. Defaults to the bundled Askama
    /// templates; override with [`AutheryConfig::with_pages`].
    #[cfg(feature = "pages")]
    pub pages: Arc<dyn Pages>,
}

impl AutheryConfig {
    pub fn new(
        key: String,
        routes: impl Into<Routes<String>>,
        #[cfg(feature = "password")] pass: PasswordConfig,
        #[cfg(feature = "email")] email: EmailConfig,
        #[cfg(feature = "oauth")] oauth: OAuthConfig,
    ) -> Result<Self, AutheryConfigError> {
        if key.as_bytes().len() < MIN_KEY_LEN {
            return Err(AutheryConfigError::KeyTooShort(key.as_bytes().len()));
        }

        Ok(Self {
            key,
            https_only: true,
            allow_signup: Allow::OnSelf,
            allow_login: Allow::OnSelf,
            routes: routes.into(),
            #[cfg(feature = "password")]
            pass,
            #[cfg(feature = "email")]
            email,
            #[cfg(feature = "oauth")]
            oauth,
            #[cfg(feature = "pages")]
            pages: Arc::new(AskamaPages),
        })
    }

    /// Replace the built-in page renderer with your own [`Pages`]
    /// implementation.
    #[cfg(feature = "pages")]
    pub fn with_pages(mut self, pages: impl Pages + 'static) -> Self {
        self.pages = Arc::new(pages);
        self
    }

    pub fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = allow_login;
        self
    }
}

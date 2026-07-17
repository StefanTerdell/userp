#[cfg(feature = "email")]
use crate::email::EmailConfig;
#[cfg(feature = "mfa")]
use crate::mfa::MfaPolicy;
#[cfg(feature = "oauth")]
use crate::oauth::OAuthConfig;
#[cfg(feature = "pages")]
use crate::pages::{AskamaPages, Pages};
#[cfg(feature = "password")]
use crate::password::PasswordConfig;
use crate::ratelimit::{NoRateLimit, RateLimiter};
#[cfg(feature = "totp")]
use crate::totp::TotpConfig;
#[cfg(feature = "webauthn")]
use crate::webauthn::WebauthnConfig;
use crate::{models::Allow, routes::Routes};
use chrono::Duration;
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
    /// Absolute lifetime of a login session. Sessions older than this are
    /// treated as logged-out and evicted. Defaults to 30 days.
    pub session_lifetime: Duration,
    /// Maximum number of concurrent sessions per user. On login past the cap,
    /// the user's oldest sessions are deleted. `None` (the default) is
    /// unlimited.
    pub max_concurrent_sessions: Option<usize>,
    /// Consulted before abusable operations (password attempts, email sends).
    /// Defaults to no limiting; see [`crate::ratelimit`].
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub routes: Routes<String>,
    #[cfg(feature = "password")]
    pub pass: PasswordConfig,
    #[cfg(feature = "email")]
    pub email: EmailConfig,
    #[cfg(feature = "oauth")]
    pub oauth: OAuthConfig,
    #[cfg(feature = "webauthn")]
    pub webauthn: WebauthnConfig,
    #[cfg(feature = "totp")]
    pub totp: TotpConfig,
    /// Which first factors demand a second one; see [`crate::mfa`]. Defaults
    /// to requiring MFA for password logins when the user has a factor
    /// registered.
    #[cfg(feature = "mfa")]
    pub mfa_policy: MfaPolicy,
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
        #[cfg(feature = "webauthn")] webauthn: WebauthnConfig,
        #[cfg(feature = "totp")] totp: TotpConfig,
    ) -> Result<Self, AutheryConfigError> {
        if key.len() < MIN_KEY_LEN {
            return Err(AutheryConfigError::KeyTooShort(key.len()));
        }

        Ok(Self {
            key,
            https_only: true,
            allow_signup: Allow::OnSelf,
            allow_login: Allow::OnSelf,
            session_lifetime: Duration::days(30),
            max_concurrent_sessions: None,
            rate_limiter: Arc::new(NoRateLimit),
            routes: routes.into(),
            #[cfg(feature = "password")]
            pass,
            #[cfg(feature = "email")]
            email,
            #[cfg(feature = "oauth")]
            oauth,
            #[cfg(feature = "webauthn")]
            webauthn,
            #[cfg(feature = "totp")]
            totp,
            #[cfg(feature = "mfa")]
            mfa_policy: MfaPolicy::default(),
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

    /// Set the absolute session lifetime.
    pub fn with_session_lifetime(mut self, session_lifetime: Duration) -> Self {
        self.session_lifetime = session_lifetime;
        self
    }

    /// Install a [`RateLimiter`] consulted before abusable operations.
    pub fn with_rate_limiter(mut self, rate_limiter: impl RateLimiter + 'static) -> Self {
        self.rate_limiter = Arc::new(rate_limiter);
        self
    }

    /// Cap concurrent sessions per user; logins past the cap evict the user's
    /// oldest sessions.
    pub fn with_max_concurrent_sessions(mut self, max: usize) -> Self {
        self.max_concurrent_sessions = Some(max);
        self
    }

    /// Set which first factors demand a second one.
    #[cfg(feature = "mfa")]
    pub fn with_mfa_policy(mut self, mfa_policy: MfaPolicy) -> Self {
        self.mfa_policy = mfa_policy;
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

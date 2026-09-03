use crate::cookie_names::CookieNames;
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
#[cfg(feature = "sms")]
use crate::sms::SmsConfig;
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
    /// Sessions unused for this long are treated as logged-out and evicted,
    /// independent of the absolute `session_lifetime`. Requires the store to
    /// track activity: `LoginSession::get_last_seen` + `touch_session`.
    /// `None` (the default) disables idle expiry.
    pub idle_timeout: Option<Duration>,
    /// Accept `Authorization: Bearer {session_id}` as an alternative to the
    /// session cookie, and expose fresh session ids to clients via an
    /// `X-Auth-Token` response header on login. For API and mobile clients;
    /// off by default. Tokens are opaque session ids: server-side, revocable,
    /// and subject to the same expiry and caps as cookie sessions.
    pub bearer_auth: bool,
    /// Previous cookie-encryption keys, accepted (read-only) during a key
    /// rotation: cookies sealed with an old key still decrypt, and re-encrypt
    /// with the current key on next write. Writes always use `key`.
    pub previous_keys: Vec<String>,
    /// A fixed prefix prepended to bearer tokens on the wire (e.g. `myapp_`),
    /// so tokens are recognizable to humans and secret scanners. Applied to
    /// the `X-Auth-Token` header and required (and stripped) when reading
    /// `Authorization: Bearer` — a token without the prefix is rejected.
    /// `None` (the default) uses the bare session id.
    pub bearer_token_prefix: Option<String>,
    /// Header holding the client address when behind a proxy (e.g.
    /// `x-forwarded-for`; the first entry is used). Without it the socket
    /// address is recorded when axum's `ConnectInfo` is available.
    pub client_ip_header: Option<String>,
    /// Names of the cookies authery sets.
    pub cookie_names: CookieNames,
    /// Consulted before abusable operations (password attempts, email sends).
    /// Defaults to no limiting; see [`crate::ratelimit`].
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Receives auth events (failed logins, rejected codes, rate-limit
    /// hits) that your store never sees. Defaults to logging through
    /// `tracing`; see [`crate::events`].
    pub events: Arc<dyn crate::events::AuthEventHandler>,
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
    #[cfg(feature = "sms")]
    pub sms: SmsConfig,
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
    // One cfg-gated positional arg per enabled method beats a builder that
    // can silently miss one.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: String,
        routes: impl Into<Routes<String>>,
        #[cfg(feature = "password")] pass: PasswordConfig,
        #[cfg(feature = "email")] email: EmailConfig,
        #[cfg(feature = "oauth")] oauth: OAuthConfig,
        #[cfg(feature = "webauthn")] webauthn: WebauthnConfig,
        #[cfg(feature = "totp")] totp: TotpConfig,
        #[cfg(feature = "sms")] sms: SmsConfig,
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
            idle_timeout: None,
            previous_keys: Vec::new(),
            bearer_auth: false,
            bearer_token_prefix: None,
            client_ip_header: None,
            cookie_names: CookieNames::default(),
            rate_limiter: Arc::new(NoRateLimit),
            events: Arc::new(crate::events::TracingEvents),
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
            #[cfg(feature = "sms")]
            sms,
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
    /// Accept previous cookie keys during rotation; see
    /// [`AutheryConfig::previous_keys`]. Keys under 64 bytes are rejected.
    pub fn with_previous_keys(
        mut self,
        keys: impl IntoIterator<Item = String>,
    ) -> Result<Self, AutheryConfigError> {
        let keys: Vec<String> = keys.into_iter().collect();
        if let Some(short) = keys.iter().find(|k| k.len() < MIN_KEY_LEN) {
            return Err(AutheryConfigError::KeyTooShort(short.len()));
        }
        self.previous_keys = keys;
        Ok(self)
    }

    /// Rename the cookies authery sets; see [`CookieNames`].
    pub fn with_cookie_names(mut self, cookie_names: CookieNames) -> Self {
        self.cookie_names = cookie_names;
        self
    }

    /// Record client addresses from this header; see
    /// [`AutheryConfig::client_ip_header`].
    pub fn with_client_ip_header(mut self, header: impl Into<String>) -> Self {
        self.client_ip_header = Some(header.into());
        self
    }

    /// Enable idle expiry; see [`AutheryConfig::idle_timeout`].
    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = Some(idle_timeout);
        self
    }

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

    /// Enable bearer-token auth for API/mobile clients; see
    /// [`AutheryConfig::bearer_auth`].
    pub fn with_bearer_auth(mut self, bearer_auth: bool) -> Self {
        self.bearer_auth = bearer_auth;
        self
    }

    /// Replace the auth-event handler; see [`crate::events`].
    pub fn with_event_handler(
        mut self,
        events: impl crate::events::AuthEventHandler + 'static,
    ) -> Self {
        self.events = Arc::new(events);
        self
    }

    /// Prefix bearer tokens on the wire; see
    /// [`AutheryConfig::bearer_token_prefix`].
    pub fn with_bearer_token_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.bearer_token_prefix = Some(prefix.into());
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

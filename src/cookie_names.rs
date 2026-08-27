//! Names of the cookies authery sets.

use serde::{Deserialize, Serialize};

/// Cookie names, configurable through
/// [`AutheryConfig::with_cookie_names`](crate::config::AutheryConfig::with_cookie_names).
/// The `*_prefix` names are followed by a per-flow key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieNames {
    /// The login session id.
    pub session_id: String,
    /// The persistent trusted-device marker.
    #[cfg(feature = "mfa")]
    pub trusted_device: String,
    /// OAuth flow state, keyed per CSRF state.
    #[cfg(feature = "oauth")]
    pub oauth_state_prefix: String,
    /// Passkey registration ceremony state, keyed per challenge.
    #[cfg(feature = "webauthn")]
    pub webauthn_register_prefix: String,
    /// Passkey login ceremony state, keyed per challenge.
    #[cfg(feature = "webauthn")]
    pub webauthn_login_prefix: String,
    /// Passkey second-factor ceremony state, keyed per challenge.
    #[cfg(all(feature = "webauthn", feature = "mfa"))]
    pub mfa_webauthn_prefix: String,
}

impl Default for CookieNames {
    fn default() -> Self {
        Self {
            session_id: "authery-session-id".into(),
            #[cfg(feature = "mfa")]
            trusted_device: "authery-trusted-device".into(),
            #[cfg(feature = "oauth")]
            oauth_state_prefix: "authery-oauth-state".into(),
            #[cfg(feature = "webauthn")]
            webauthn_register_prefix: "authery-webauthn-reg".into(),
            #[cfg(feature = "webauthn")]
            webauthn_login_prefix: "authery-webauthn-auth".into(),
            #[cfg(all(feature = "webauthn", feature = "mfa"))]
            mfa_webauthn_prefix: "authery-mfa-webauthn".into(),
        }
    }
}

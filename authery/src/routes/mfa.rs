//! Routes for completing a second factor on a pending MFA session.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MfaRoutes<T = &'static str> {
    /// Get - renders the second-factor picker page (when `pages` is active)
    pub login_mfa: T,
    #[cfg(feature = "otp")]
    /// Post without `code` - mails a code to the pending user's verified address
    /// Post with `code` - verifies it and completes the login
    pub login_mfa_otp: T,
    #[cfg(feature = "totp")]
    /// Post - verifies an authenticator-app code and completes the login
    pub login_mfa_totp: T,
    #[cfg(feature = "webauthn")]
    /// Post - begins the second-factor passkey ceremony (JSON challenge)
    pub login_mfa_webauthn_start: T,
    #[cfg(feature = "webauthn")]
    /// Post - receives the JSON assertion and completes the login
    pub login_mfa_webauthn_finish: T,
}

impl Default for MfaRoutes {
    fn default() -> Self {
        Self {
            login_mfa: "/login/mfa",
            #[cfg(feature = "otp")]
            login_mfa_otp: "/login/mfa/otp",
            #[cfg(feature = "totp")]
            login_mfa_totp: "/login/mfa/totp",
            #[cfg(feature = "webauthn")]
            login_mfa_webauthn_start: "/login/mfa/webauthn/start",
            #[cfg(feature = "webauthn")]
            login_mfa_webauthn_finish: "/login/mfa/webauthn/finish",
        }
    }
}

impl<'a> From<&'a MfaRoutes<String>> for MfaRoutes<&'a str> {
    fn from(value: &'a MfaRoutes<String>) -> Self {
        Self {
            login_mfa: &value.login_mfa,
            #[cfg(feature = "otp")]
            login_mfa_otp: &value.login_mfa_otp,
            #[cfg(feature = "totp")]
            login_mfa_totp: &value.login_mfa_totp,
            #[cfg(feature = "webauthn")]
            login_mfa_webauthn_start: &value.login_mfa_webauthn_start,
            #[cfg(feature = "webauthn")]
            login_mfa_webauthn_finish: &value.login_mfa_webauthn_finish,
        }
    }
}

impl From<MfaRoutes<&str>> for MfaRoutes<String> {
    fn from(value: MfaRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<MfaRoutes<T>> for MfaRoutes<T> {
    fn as_ref(&self) -> &MfaRoutes<T> {
        self
    }
}

impl<T: Display> MfaRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> MfaRoutes<String> {
        MfaRoutes {
            login_mfa: format!("{prefix}{}", self.login_mfa),
            #[cfg(feature = "otp")]
            login_mfa_otp: format!("{prefix}{}", self.login_mfa_otp),
            #[cfg(feature = "totp")]
            login_mfa_totp: format!("{prefix}{}", self.login_mfa_totp),
            #[cfg(feature = "webauthn")]
            login_mfa_webauthn_start: format!("{prefix}{}", self.login_mfa_webauthn_start),
            #[cfg(feature = "webauthn")]
            login_mfa_webauthn_finish: format!("{prefix}{}", self.login_mfa_webauthn_finish),
        }
    }
}

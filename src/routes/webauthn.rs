//! Routes for the webauthn (passkey) ceremonies. These are JSON endpoints
//! driven by the inline page scripts (or your own frontend), not
//! browser-navigated pages.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebauthnRoutes<T = &'static str> {
    /// Post - begins a discoverable passkey login; returns the JSON challenge
    /// for `navigator.credentials.get()`
    pub login_webauthn_start: T,
    /// Post - receives the JSON assertion, verifies it, creates the session
    pub login_webauthn_finish: T,
    /// Post - begins passkey registration for the logged-in user; returns the
    /// JSON challenge for `navigator.credentials.create()`
    pub user_webauthn_register_start: T,
    /// Post - receives the JSON attestation and stores the new passkey
    pub user_webauthn_register_finish: T,
    #[cfg(feature = "user")]
    /// Post - deletes one of the logged-in user's passkeys by hex credential id
    pub user_webauthn_delete: T,
}

impl Default for WebauthnRoutes {
    fn default() -> Self {
        Self {
            login_webauthn_start: "/login/webauthn/start",
            login_webauthn_finish: "/login/webauthn/finish",
            user_webauthn_register_start: "/user/webauthn/register/start",
            user_webauthn_register_finish: "/user/webauthn/register/finish",
            #[cfg(feature = "user")]
            user_webauthn_delete: "/user/webauthn/delete",
        }
    }
}

impl<'a> From<&'a WebauthnRoutes<String>> for WebauthnRoutes<&'a str> {
    fn from(value: &'a WebauthnRoutes<String>) -> Self {
        Self {
            login_webauthn_start: &value.login_webauthn_start,
            login_webauthn_finish: &value.login_webauthn_finish,
            user_webauthn_register_start: &value.user_webauthn_register_start,
            user_webauthn_register_finish: &value.user_webauthn_register_finish,
            #[cfg(feature = "user")]
            user_webauthn_delete: &value.user_webauthn_delete,
        }
    }
}

impl From<WebauthnRoutes<&str>> for WebauthnRoutes<String> {
    fn from(value: WebauthnRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<WebauthnRoutes<T>> for WebauthnRoutes<T> {
    fn as_ref(&self) -> &WebauthnRoutes<T> {
        self
    }
}

impl<T: Display> WebauthnRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> WebauthnRoutes<String> {
        WebauthnRoutes {
            login_webauthn_start: format!("{prefix}{}", self.login_webauthn_start),
            login_webauthn_finish: format!("{prefix}{}", self.login_webauthn_finish),
            user_webauthn_register_start: format!("{prefix}{}", self.user_webauthn_register_start),
            user_webauthn_register_finish: format!(
                "{prefix}{}",
                self.user_webauthn_register_finish
            ),
            #[cfg(feature = "user")]
            user_webauthn_delete: format!("{prefix}{}", self.user_webauthn_delete),
        }
    }
}

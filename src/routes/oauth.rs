//! Contains OAuthRoutes and associated helper functions

pub mod actions;

use self::actions::*;

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// The OAuth routes: the action routes that initiate flows, and the single
/// callback route every flow returns to (the flow type and provider are
/// recovered from the encrypted state cookie, so no path segments needed).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthRoutes<T = &'static str> {
    /// Contains routes used to initiate the OAuth login, signup, link and refresh flows
    pub actions: OAuthActionRoutes<T>,
    /// Get - Receives every OAuth callback. This is the redirect URI to
    /// register with your providers (as an absolute URL on your base_url).
    pub callback: T,
}

impl Default for OAuthRoutes<&'static str> {
    fn default() -> Self {
        Self {
            actions: OAuthActionRoutes::default(),
            callback: "/oauth",
        }
    }
}

impl<'a> From<&'a OAuthRoutes<String>> for OAuthRoutes<&'a str> {
    fn from(value: &'a OAuthRoutes<String>) -> Self {
        Self {
            actions: value.actions.as_ref().into(),
            callback: &value.callback,
        }
    }
}

impl From<OAuthRoutes<&str>> for OAuthRoutes<String> {
    fn from(value: OAuthRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<OAuthRoutes<T>> for OAuthRoutes<T> {
    fn as_ref(&self) -> &OAuthRoutes<T> {
        self
    }
}

impl<T: Display> OAuthRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> OAuthRoutes<String> {
        OAuthRoutes {
            actions: self.actions.with_prefix(&prefix),
            callback: format!("{prefix}{}", self.callback),
        }
    }
}

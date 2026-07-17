//! Contains OAuthRoutes and associated helper functions

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// The OAuth routes: the action routes that initiate flows, and the single
/// callback route every flow returns to (the flow type and provider are
/// recovered from the encrypted state cookie, so no path segments needed).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthRoutes<T = &'static str> {
    /// Post - Initiate the OAuth login flow
    pub login_oauth: T,
    /// Post - Initiate the OAuth signup flow
    pub signup_oauth: T,
    /// Post - Initiate the OAuth link flow
    pub user_oauth_link: T,
    /// Post - Initiate the OAuth refresh flow
    pub user_oauth_refresh: T,
    /// Get - Receives every OAuth callback. This is the redirect URI to
    /// register with your providers (as an absolute URL on your base_url).
    pub callback: T,
}

impl Default for OAuthRoutes<&'static str> {
    fn default() -> Self {
        Self {
            login_oauth: "/login/oauth",
            signup_oauth: "/signup/oauth",
            user_oauth_link: "/user/oauth/link",
            user_oauth_refresh: "/user/oauth/refresh",
            callback: "/oauth/callback",
        }
    }
}

impl<'a> From<&'a OAuthRoutes<String>> for OAuthRoutes<&'a str> {
    fn from(value: &'a OAuthRoutes<String>) -> Self {
        Self {
            login_oauth: &value.login_oauth,
            signup_oauth: &value.signup_oauth,
            user_oauth_link: &value.user_oauth_link,
            user_oauth_refresh: &value.user_oauth_refresh,
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
            login_oauth: format!("{prefix}{}", self.login_oauth),
            signup_oauth: format!("{prefix}{}", self.signup_oauth),
            user_oauth_link: format!("{prefix}{}", self.user_oauth_link),
            user_oauth_refresh: format!("{prefix}{}", self.user_oauth_refresh),
            callback: format!("{prefix}{}", self.callback),
        }
    }
}

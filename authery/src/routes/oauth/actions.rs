//! Contains OAuthActionRoutes and associated helper functions.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Contains routes used to initiate the OAuth login, signup, link and refresh flows
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthActionRoutes<T = &'static str> {
    /// Post - Initiate the OAuth login flow
    pub login_oauth: T,
    /// Post - Initiate the OAuth signup flow
    pub signup_oauth: T,
    /// Post - Initiate the OAuth link flow
    pub user_oauth_link: T,
    /// Post - Initiate the OAuth refresh flow
    pub user_oauth_refresh: T,
}

impl Default for OAuthActionRoutes {
    fn default() -> Self {
        Self {
            login_oauth: "/login/oauth",
            signup_oauth: "/signup/oauth",
            user_oauth_link: "/user/oauth/link",
            user_oauth_refresh: "/user/oauth/refresh",
        }
    }
}

impl<'a> From<&'a OAuthActionRoutes<String>> for OAuthActionRoutes<&'a str> {
    fn from(value: &'a OAuthActionRoutes<String>) -> Self {
        Self {
            login_oauth: &value.login_oauth,
            signup_oauth: &value.signup_oauth,
            user_oauth_link: &value.user_oauth_link,
            user_oauth_refresh: &value.user_oauth_refresh,
        }
    }
}

impl From<OAuthActionRoutes<&str>> for OAuthActionRoutes<String> {
    fn from(value: OAuthActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<OAuthActionRoutes<T>> for OAuthActionRoutes<T> {
    fn as_ref(&self) -> &OAuthActionRoutes<T> {
        self
    }
}

impl<T: Display> OAuthActionRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> OAuthActionRoutes<String> {
        OAuthActionRoutes {
            login_oauth: format!("{prefix}{}", self.login_oauth),
            signup_oauth: format!("{prefix}{}", self.signup_oauth),
            user_oauth_link: format!("{prefix}{}", self.user_oauth_link),
            user_oauth_refresh: format!("{prefix}{}", self.user_oauth_refresh),
        }
    }
}

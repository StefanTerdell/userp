//! Contains Routes and associated helper functions

pub mod pages;
use pages::*;

#[cfg(feature = "account")]
pub mod account;
#[cfg(feature = "account")]
use account::*;
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "email")]
use email::*;
#[cfg(feature = "oauth-callbacks")]
pub mod oauth;
#[cfg(feature = "oauth-callbacks")]
use oauth::*;
#[cfg(feature = "password")]
pub mod password;
#[cfg(feature = "password")]
use password::*;
use serde::{Deserialize, Serialize};

use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Routes contain the relative URL paths of all actions, callbacks and pages used by Userp to recieve and redirect requests
pub struct Routes<T = String> {
    /// PageRoutes contain all the routes the user may visit to for instance log in or manage their account
    pub pages: PageRoutes<T>,
    #[cfg(feature = "oauth-callbacks")]
    /// Contains the OAuthCallbackRouts and - if the `oauth` feature is enabled - the OAuthActionRoutes (login, signup etc.)
    pub oauth: OAuthRoutes<T>,
    #[cfg(feature = "email")]
    /// Contains routes used in the Email login and signup (and - if the password feature is active - reset) flows
    pub email: EmailActionRoutes<T>,
    #[cfg(feature = "password")]
    /// Contains routes associated with logging in and signing up using the Password method
    pub password: PasswordActionRoutes<T>,
    #[cfg(feature = "account")]
    /// Contains routes used to control the user account and associated entities
    pub account: AccountActionRoutes<T>,
    /// Get - deletes the current UserLogin session and redirects the user to pages.post_logout
    pub logout: T,
    /// Get - returns 200 if the current session is still present on the server. Returns 401 if not.
    pub user_verify_session: T,
}

impl Default for Routes<&'static str> {
    fn default() -> Self {
        Routes {
            pages: PageRoutes::default(),
            #[cfg(feature = "oauth-callbacks")]
            oauth: OAuthRoutes::default(),
            #[cfg(feature = "email")]
            email: EmailActionRoutes::default(),
            #[cfg(feature = "password")]
            password: PasswordActionRoutes::default(),
            #[cfg(feature = "account")]
            account: AccountActionRoutes::default(),
            user_verify_session: "/verify-session",
            logout: "/logout",
        }
    }
}

impl From<Routes<&'static str>> for Routes<String> {
    fn from(value: Routes<&'static str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<Routes<T>> for Routes<T> {
    fn as_ref(&self) -> &Routes<T> {
        self
    }
}

impl<'a> From<&'a Routes<String>> for Routes<&'a str> {
    fn from(value: &'a Routes<String>) -> Self {
        Self {
            pages: value.pages.as_ref().into(),
            #[cfg(feature = "oauth-callbacks")]
            oauth: value.oauth.as_ref().into(),
            #[cfg(feature = "email")]
            email: value.email.as_ref().into(),
            #[cfg(feature = "password")]
            password: value.password.as_ref().into(),
            #[cfg(feature = "account")]
            account: value.account.as_ref().into(),
            user_verify_session: &value.user_verify_session,
            logout: &value.logout,
        }
    }
}

impl<T: Display> Routes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> Routes<String> {
        Routes {
            pages: self.pages.with_prefix(&prefix),
            #[cfg(feature = "oauth-callbacks")]
            oauth: self.oauth.with_prefix(&prefix),
            #[cfg(feature = "email")]
            email: self.email.with_prefix(&prefix),
            #[cfg(feature = "password")]
            password: self.password.with_prefix(&prefix),
            #[cfg(feature = "account")]
            account: self.account.with_prefix(&prefix),
            user_verify_session: format!("{prefix}{}", self.user_verify_session),
            logout: format!("{prefix}{}", self.logout),
        }
    }
}

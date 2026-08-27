//! Contains PageRoutes and associated helper functions

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// PageRoutes contain all the routes the user may visit to for instance log in or manage their account
pub struct PageRoutes<T = &'static str> {
    /// The default route to redirect to after logging in or signing up
    pub post_login: T,
    /// The default route to redirect to after logging out
    pub post_logout: T,
    /// The route a user should visit if they wish to log in
    pub login: T,
    /// The route a user should visit if they wish to sign up
    pub signup: T,
    /// The users account page
    #[cfg(feature = "user")]
    pub user: T,
    /// The main website page. Used in the default account page to go "home"
    #[cfg(feature = "user")]
    pub home: T,
    /// On this page the user can initiate a password reset by entering their email
    #[cfg(all(feature = "password", feature = "email"))]
    pub password_send_reset: T,
    /// On this page the user can conclude a password reset by entering a new one
    #[cfg(all(feature = "password", feature = "email"))]
    pub password_reset: T,
    /// Confirms that an emailed link was sent
    #[cfg(feature = "email")]
    pub email_sent: T,
    /// Shown when an emailed link has expired
    #[cfg(feature = "email")]
    pub email_expired: T,
    /// Shown when the rate limiter refuses an attempt
    pub paused: T,
}

impl Default for PageRoutes {
    fn default() -> Self {
        Self {
            post_login: "/",
            post_logout: "/",
            login: "/login",
            signup: "/signup",
            #[cfg(feature = "user")]
            user: "/user",
            #[cfg(feature = "user")]
            home: "/",
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: "/password/reset/send",
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: "/password/reset",
            #[cfg(feature = "email")]
            email_sent: "/email/sent",
            #[cfg(feature = "email")]
            email_expired: "/email/expired",
            paused: "/paused",
        }
    }
}

impl<'a> From<&'a PageRoutes<String>> for PageRoutes<&'a str> {
    fn from(value: &'a PageRoutes<String>) -> Self {
        Self {
            post_login: &value.post_login,
            post_logout: &value.post_logout,
            login: &value.login,
            signup: &value.signup,
            #[cfg(feature = "user")]
            user: &value.user,
            #[cfg(feature = "user")]
            home: &value.home,
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: &value.password_send_reset,
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: &value.password_reset,
            #[cfg(feature = "email")]
            email_sent: &value.email_sent,
            #[cfg(feature = "email")]
            email_expired: &value.email_expired,
            paused: &value.paused,
        }
    }
}

impl From<PageRoutes<&str>> for PageRoutes<String> {
    fn from(value: PageRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<PageRoutes<T>> for PageRoutes<T> {
    fn as_ref(&self) -> &PageRoutes<T> {
        self
    }
}

impl<T: Display> PageRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> PageRoutes<String> {
        PageRoutes {
            post_login: format!("{prefix}{}", self.post_login),
            post_logout: format!("{prefix}{}", self.post_logout),
            login: format!("{prefix}{}", self.login),
            signup: format!("{prefix}{}", self.signup),
            #[cfg(feature = "user")]
            user: format!("{prefix}{}", self.user),
            #[cfg(feature = "user")]
            home: format!("{prefix}{}", self.home),
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: format!("{prefix}{}", self.password_send_reset),
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: format!("{prefix}{}", self.password_reset),
            #[cfg(feature = "email")]
            email_sent: format!("{prefix}{}", self.email_sent),
            #[cfg(feature = "email")]
            email_expired: format!("{prefix}{}", self.email_expired),
            paused: format!("{prefix}{}", self.paused),
        }
    }
}

//! Contains EmailActionRoutes and associated helper functions

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]

/// Contains routes used in the Email login and signup (and - if the password feature is active - reset) flows
pub struct EmailActionRoutes<T = &'static str> {
    /// Post - Initiate an Email login by creating an EmailChallenge and sending the link
    /// Get - Receives the challenge code, and creates the LoginSession using the Email method
    pub login_email: T,
    /// Post - Initiate an Email signup by creating an EmailChallenge and sending the link
    /// Get - Receives the link and code, and creates the LoginSession using the Email method
    pub signup_email: T,
    /// Post - Initiate an Email verification by creating an EmailChallenge and sending the link
    /// Get - Receives the challenge code, and verifies the address. Does NOT create a LoginSession
    pub user_email_verify: T,
    #[cfg(feature = "password")]
    /// Post - Sets the users new password. Requires a LoginSession using the PasswordReset method
    pub password_reset: T,
    /// Get - Receives the challenge code, and creates a LoginSession using the PasswordReset method
    #[cfg(feature = "password")]
    pub password_reset_callback: T,
    /// Post - Initiate a Password Reset by creating an EmailChallenge and sending the link
    #[cfg(feature = "password")]
    pub password_send_reset: T,
}

impl Default for EmailActionRoutes {
    fn default() -> Self {
        Self {
            login_email: "/login/email",
            signup_email: "/signup/email",
            user_email_verify: "/user/email/verify",
            #[cfg(feature = "password")]
            password_reset: "/password/reset",
            #[cfg(feature = "password")]
            password_reset_callback: "/password/reset-callback",
            #[cfg(feature = "password")]
            password_send_reset: "/password/send-reset",
        }
    }
}

impl<'a> From<&'a EmailActionRoutes<String>> for EmailActionRoutes<&'a str> {
    fn from(value: &'a EmailActionRoutes<String>) -> Self {
        Self {
            login_email: &value.login_email,
            signup_email: &value.signup_email,
            user_email_verify: &value.user_email_verify,
            #[cfg(feature = "password")]
            password_reset: &value.password_reset,
            #[cfg(feature = "password")]
            password_reset_callback: &value.password_reset_callback,
            #[cfg(feature = "password")]
            password_send_reset: &value.password_send_reset,
        }
    }
}

impl From<EmailActionRoutes<&str>> for EmailActionRoutes<String> {
    fn from(value: EmailActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<EmailActionRoutes<T>> for EmailActionRoutes<T> {
    fn as_ref(&self) -> &EmailActionRoutes<T> {
        self
    }
}

impl<T: Display> EmailActionRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> EmailActionRoutes<String> {
        EmailActionRoutes {
            login_email: format!("{prefix}{}", self.login_email),
            signup_email: format!("{prefix}{}", self.signup_email),
            user_email_verify: format!("{prefix}{}", self.user_email_verify),
            #[cfg(feature = "password")]
            password_send_reset: format!("{prefix}{}", self.password_send_reset),
            #[cfg(feature = "password")]
            password_reset: format!("{prefix}{}", self.password_reset),
            #[cfg(feature = "password")]
            password_reset_callback: format!("{prefix}{}", self.password_reset_callback),
        }
    }
}

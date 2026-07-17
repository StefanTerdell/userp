//! Routes for the SMS one-time-code flows.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SmsActionRoutes<T = &'static str> {
    /// Post without `code` - sends a one-time code to the number
    /// Post with `code` - verifies the code and creates the LoginSession
    /// Get - renders the code-entry page (when the `pages` feature is active)
    pub login_sms: T,
    /// As `login_sms`, but for signup
    pub signup_sms: T,
}

impl Default for SmsActionRoutes {
    fn default() -> Self {
        Self {
            login_sms: "/login/sms",
            signup_sms: "/signup/sms",
        }
    }
}

impl<'a> From<&'a SmsActionRoutes<String>> for SmsActionRoutes<&'a str> {
    fn from(value: &'a SmsActionRoutes<String>) -> Self {
        Self {
            login_sms: &value.login_sms,
            signup_sms: &value.signup_sms,
        }
    }
}

impl From<SmsActionRoutes<&str>> for SmsActionRoutes<String> {
    fn from(value: SmsActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<SmsActionRoutes<T>> for SmsActionRoutes<T> {
    fn as_ref(&self) -> &SmsActionRoutes<T> {
        self
    }
}

impl<T: Display> SmsActionRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> SmsActionRoutes<String> {
        SmsActionRoutes {
            login_sms: format!("{prefix}{}", self.login_sms),
            signup_sms: format!("{prefix}{}", self.signup_sms),
        }
    }
}

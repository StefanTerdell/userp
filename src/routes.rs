//! Contains Routes and associated helper functions

pub mod pages;
use pages::*;

#[cfg(feature = "user")]
pub mod user;
#[cfg(feature = "user")]
use user::*;
#[cfg(any(feature = "email", feature = "otp"))]
pub mod email;
#[cfg(any(feature = "email", feature = "otp"))]
use email::*;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "oauth")]
use oauth::*;
#[cfg(feature = "password")]
pub mod password;
#[cfg(feature = "password")]
use password::*;
#[cfg(feature = "webauthn")]
pub mod webauthn;
#[cfg(feature = "webauthn")]
use webauthn::*;
#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "mfa")]
use mfa::*;
#[cfg(feature = "sms")]
pub mod sms;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sms")]
use sms::*;

use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Routes contain the relative URL paths of all actions, callbacks and pages used by Authery to recieve and redirect requests
pub struct Routes<T = String> {
    /// PageRoutes contain all the routes the user may visit to for instance log in or manage their account
    pub pages: PageRoutes<T>,
    #[cfg(feature = "oauth")]
    /// The OAuth action routes (login, signup etc.) and the single callback route
    pub oauth: OAuthRoutes<T>,
    #[cfg(any(feature = "email", feature = "otp"))]
    /// Contains routes used in the Email login and signup (and - if the password feature is active - reset) flows
    pub email: EmailActionRoutes<T>,
    #[cfg(feature = "password")]
    /// Contains routes associated with logging in and signing up using the Password method
    pub password: PasswordActionRoutes<T>,
    #[cfg(feature = "user")]
    /// Contains routes used to control the user account and associated entities
    pub user: UserActionRoutes<T>,
    #[cfg(feature = "webauthn")]
    /// Contains the JSON endpoints for the webauthn (passkey) ceremonies
    pub webauthn: WebauthnRoutes<T>,
    #[cfg(feature = "mfa")]
    /// Contains the routes for completing a second factor
    pub mfa: MfaRoutes<T>,
    #[cfg(feature = "sms")]
    /// Contains the SMS one-time-code routes
    pub sms: SmsActionRoutes<T>,
    /// Post - deletes the current UserLogin session and redirects the user to pages.post_logout
    pub logout: T,
    /// Get - returns 200 if the current session is still present on the server. Returns 401 if not.
    pub user_verify_session: T,
}

impl Default for Routes<&'static str> {
    fn default() -> Self {
        Routes {
            pages: PageRoutes::default(),
            #[cfg(feature = "oauth")]
            oauth: OAuthRoutes::default(),
            #[cfg(any(feature = "email", feature = "otp"))]
            email: EmailActionRoutes::default(),
            #[cfg(feature = "password")]
            password: PasswordActionRoutes::default(),
            #[cfg(feature = "user")]
            user: UserActionRoutes::default(),
            #[cfg(feature = "webauthn")]
            webauthn: WebauthnRoutes::default(),
            #[cfg(feature = "mfa")]
            mfa: MfaRoutes::default(),
            #[cfg(feature = "sms")]
            sms: SmsActionRoutes::default(),
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
            #[cfg(feature = "oauth")]
            oauth: value.oauth.as_ref().into(),
            #[cfg(any(feature = "email", feature = "otp"))]
            email: value.email.as_ref().into(),
            #[cfg(feature = "password")]
            password: value.password.as_ref().into(),
            #[cfg(feature = "user")]
            user: value.user.as_ref().into(),
            #[cfg(feature = "webauthn")]
            webauthn: value.webauthn.as_ref().into(),
            #[cfg(feature = "mfa")]
            mfa: value.mfa.as_ref().into(),
            #[cfg(feature = "sms")]
            sms: value.sms.as_ref().into(),
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
            #[cfg(feature = "oauth")]
            oauth: self.oauth.with_prefix(&prefix),
            #[cfg(any(feature = "email", feature = "otp"))]
            email: self.email.with_prefix(&prefix),
            #[cfg(feature = "password")]
            password: self.password.with_prefix(&prefix),
            #[cfg(feature = "user")]
            user: self.user.with_prefix(&prefix),
            #[cfg(feature = "webauthn")]
            webauthn: self.webauthn.with_prefix(&prefix),
            #[cfg(feature = "mfa")]
            mfa: self.mfa.with_prefix(&prefix),
            #[cfg(feature = "sms")]
            sms: self.sms.with_prefix(&prefix),
            user_verify_session: format!("{prefix}{}", self.user_verify_session),
            logout: format!("{prefix}{}", self.logout),
        }
    }
}

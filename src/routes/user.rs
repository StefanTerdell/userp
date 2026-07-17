//! Contains UserActionRoutes and associated helper functions

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Contains routes used to control the user account and associated entities
/// that are not specifically required by the login/signup flows
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserActionRoutes<T = &'static str> {
    /// Post route to delete a user account
    pub user_delete: T,
    #[cfg(feature = "totp")]
    /// Post - begins TOTP enrollment; renders the QR/confirm page
    pub user_totp_enroll: T,
    #[cfg(feature = "totp")]
    /// Post - confirms enrollment with a code from the authenticator
    pub user_totp_confirm: T,
    #[cfg(feature = "totp")]
    /// Post - removes the TOTP enrollment
    pub user_totp_disable: T,
    /// Post route to delete a login session
    pub user_session_delete: T,
    /// Post route to add a user email
    #[cfg(feature = "email")]
    pub user_email_add: T,
    /// Post route to delete a user email
    #[cfg(feature = "email")]
    pub user_email_delete: T,
    /// Post route to disable Email login for a User Email
    #[cfg(feature = "email")]
    pub user_email_disable_login: T,
    /// Post route to enable Email login for a User Email
    #[cfg(feature = "email")]
    pub user_email_enable_login: T,
    /// Post route to delete an OAuth token
    #[cfg(feature = "oauth")]
    pub user_oauth_delete: T,
    #[cfg(feature = "password")]
    /// Post route to remove the users password
    pub user_password_delete: T,
    #[cfg(feature = "password")]
    /// Post route to set the users password
    pub user_password_set: T,
}

impl Default for UserActionRoutes {
    fn default() -> Self {
        Self {
            user_delete: "/user/delete",
            #[cfg(feature = "totp")]
            user_totp_enroll: "/user/totp/enroll",
            #[cfg(feature = "totp")]
            user_totp_confirm: "/user/totp/confirm",
            #[cfg(feature = "totp")]
            user_totp_disable: "/user/totp/disable",
            user_session_delete: "/user/session/delete",
            #[cfg(feature = "email")]
            user_email_add: "/user/email/add",
            #[cfg(feature = "email")]
            user_email_delete: "/user/email/delete",
            #[cfg(feature = "email")]
            user_email_disable_login: "/user/email/disable_login",
            #[cfg(feature = "email")]
            user_email_enable_login: "/user/email/enable_login",
            #[cfg(feature = "oauth")]
            user_oauth_delete: "/user/oauth/delete",
            #[cfg(feature = "password")]
            user_password_delete: "/user/password/delete",
            #[cfg(feature = "password")]
            user_password_set: "/user/password/set",
        }
    }
}

impl<'a> From<&'a UserActionRoutes<String>> for UserActionRoutes<&'a str> {
    fn from(value: &'a UserActionRoutes<String>) -> Self {
        Self {
            user_delete: &value.user_delete,
            #[cfg(feature = "totp")]
            user_totp_enroll: &value.user_totp_enroll,
            #[cfg(feature = "totp")]
            user_totp_confirm: &value.user_totp_confirm,
            #[cfg(feature = "totp")]
            user_totp_disable: &value.user_totp_disable,
            user_session_delete: &value.user_session_delete,
            #[cfg(feature = "email")]
            user_email_add: &value.user_email_add,
            #[cfg(feature = "email")]
            user_email_delete: &value.user_email_delete,
            #[cfg(feature = "email")]
            user_email_disable_login: &value.user_email_disable_login,
            #[cfg(feature = "email")]
            user_email_enable_login: &value.user_email_enable_login,
            #[cfg(feature = "oauth")]
            user_oauth_delete: &value.user_oauth_delete,
            #[cfg(feature = "password")]
            user_password_delete: &value.user_password_delete,
            #[cfg(feature = "password")]
            user_password_set: &value.user_password_set,
        }
    }
}

impl From<UserActionRoutes<&str>> for UserActionRoutes<String> {
    fn from(value: UserActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<UserActionRoutes<T>> for UserActionRoutes<T> {
    fn as_ref(&self) -> &UserActionRoutes<T> {
        self
    }
}

impl<T: Display> UserActionRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> UserActionRoutes<String> {
        UserActionRoutes {
            user_delete: format!("{prefix}{}", self.user_delete),
            #[cfg(feature = "totp")]
            user_totp_enroll: format!("{prefix}{}", self.user_totp_enroll),
            #[cfg(feature = "totp")]
            user_totp_confirm: format!("{prefix}{}", self.user_totp_confirm),
            #[cfg(feature = "totp")]
            user_totp_disable: format!("{prefix}{}", self.user_totp_disable),
            user_session_delete: format!("{prefix}{}", self.user_session_delete),
            #[cfg(feature = "password")]
            user_password_set: format!("{prefix}{}", self.user_password_set),
            #[cfg(feature = "password")]
            user_password_delete: format!("{prefix}{}", self.user_password_delete),
            #[cfg(feature = "oauth")]
            user_oauth_delete: format!("{prefix}{}", self.user_oauth_delete),
            #[cfg(feature = "email")]
            user_email_add: format!("{prefix}{}", self.user_email_add),
            #[cfg(feature = "email")]
            user_email_delete: format!("{prefix}{}", self.user_email_delete),
            #[cfg(feature = "email")]
            user_email_enable_login: format!("{prefix}{}", self.user_email_enable_login),
            #[cfg(feature = "email")]
            user_email_disable_login: format!("{prefix}{}", self.user_email_disable_login),
        }
    }
}

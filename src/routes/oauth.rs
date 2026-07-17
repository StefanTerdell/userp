//! Contains OAuthRoutes and associated helper functions

#[cfg(feature = "oauth")]
pub mod actions;
pub mod callbacks;

#[cfg(feature = "oauth")]
use self::actions::*;
use self::callbacks::*;

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Contains the OAuthCallbackRouts and - if the `oauth` feature is enabled - the OAuthActionRoutes (login, signup etc.)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthRoutes<T = &'static str> {
    /// Contains routes used to initiate the OAuth login, signup, link and refresh flows
    #[cfg(feature = "oauth")]
    pub actions: OAuthActionRoutes<T>,
    /// Contains routes used to recieve the OAuth login, signup, link and refresh callbacks
    /// Setting all callback routes to the same route is supported.
    pub callbacks: OAuthCallbackRoutes<T>,
}

impl Default for OAuthRoutes<&'static str> {
    fn default() -> Self {
        Self {
            #[cfg(feature = "oauth")]
            actions: OAuthActionRoutes::default(),
            callbacks: OAuthCallbackRoutes::default(),
        }
    }
}

impl<'a> From<&'a OAuthRoutes<String>> for OAuthRoutes<&'a str> {
    fn from(value: &'a OAuthRoutes<String>) -> Self {
        Self {
            #[cfg(feature = "oauth")]
            actions: value.actions.as_ref().into(),
            callbacks: value.callbacks.as_ref().into(),
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
            #[cfg(feature = "oauth")]
            actions: self.actions.with_prefix(&prefix),
            callbacks: self.callbacks.with_prefix(prefix),
        }
    }
}

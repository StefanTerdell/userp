pub mod hasher;
pub mod login;
pub mod signup;

use self::hasher::{DefaultPasswordHasher, PasswordHasher};
use crate::models::Allow;
use std::sync::Arc;

#[cfg(feature = "email")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordReset {
    Never,
    VerifiedEmailOnly,
    AnyUserEmail,
}

#[derive(Debug, Clone)]
pub struct PasswordConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    #[cfg(feature = "email")]
    pub allow_reset: PasswordReset,
    pub hasher: Arc<dyn PasswordHasher>,
}

impl PasswordConfig {
    pub fn new() -> Self {
        Self {
            allow_login: None,
            allow_signup: None,
            #[cfg(feature = "email")]
            allow_reset: PasswordReset::VerifiedEmailOnly,
            hasher: Arc::new(DefaultPasswordHasher),
        }
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    #[cfg(feature = "email")]
    pub fn with_allow_reset(mut self, allow_reset: PasswordReset) -> Self {
        self.allow_reset = allow_reset;
        self
    }

    pub fn with_hasher(mut self, hasher: impl PasswordHasher + 'static) -> Self {
        self.hasher = Arc::new(hasher);
        self
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self::new()
    }
}

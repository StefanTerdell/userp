pub mod hasher;
pub mod login;
pub mod signup;

use self::hasher::{DefaultPasswordHasher, PasswordHasher};
use crate::core::CoreAuthery;
use crate::models::{Allow, AutheryCookies};
use crate::store::AutheryStore;
use std::sync::Arc;

/// A requirement new passwords must satisfy: a regular expression matched
/// against the whole password, plus an optional human-readable hint. The
/// pattern is also handed to the bundled pages as the input's `pattern`
/// attribute, so keep it valid for both Rust `regex` and HTML (no lookaround).
#[derive(Debug, Clone)]
pub struct PasswordPattern {
    regex: regex::Regex,
    pattern: String,
    hint: Option<String>,
}

impl PasswordPattern {
    pub fn new(pattern: &str, hint: Option<&str>) -> Result<Self, regex::Error> {
        Ok(Self {
            regex: regex::Regex::new(&format!("^(?:{pattern})$"))?,
            pattern: pattern.to_owned(),
            hint: hint.map(str::to_owned),
        })
    }

    /// The pattern as given, for an `<input pattern="...">`.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    pub fn is_match(&self, password: &str) -> bool {
        self.regex.is_match(password)
    }
}

impl Default for PasswordPattern {
    /// At least eight characters.
    fn default() -> Self {
        Self::new(".{8,}", Some("At least 8 characters")).expect("valid default pattern")
    }
}

/// A new password failed [`PasswordConfig::pattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRejected {
    pub hint: Option<String>,
}

impl std::error::Error for PasswordRejected {}

impl std::fmt::Display for PasswordRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.hint {
            Some(hint) => write!(f, "Password does not meet the requirements: {hint}"),
            None => f.write_str("Password does not meet the requirements"),
        }
    }
}

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
    /// Requirement for new passwords; `None` accepts anything. Defaults to
    /// [`PasswordPattern::default`].
    pub pattern: Option<PasswordPattern>,
}

impl PasswordConfig {
    pub fn new() -> Self {
        Self {
            allow_login: None,
            allow_signup: None,
            #[cfg(feature = "email")]
            allow_reset: PasswordReset::VerifiedEmailOnly,
            hasher: Arc::new(DefaultPasswordHasher),
            pattern: Some(PasswordPattern::default()),
        }
    }

    pub fn with_pattern(mut self, pattern: Option<PasswordPattern>) -> Self {
        self.pattern = pattern;
        self
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

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Check a new password against [`PasswordConfig::pattern`] and hash it.
    pub async fn new_password_hash(&self, password: &str) -> Result<String, PasswordRejected> {
        if let Some(pattern) = &self.pass.pattern
            && !pattern.is_match(password)
        {
            return Err(PasswordRejected {
                hint: pattern.hint().map(str::to_owned),
            });
        }
        Ok(self.pass.hasher.generate_hash(password.to_owned()).await)
    }
}

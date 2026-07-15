#[cfg(feature = "email")]
use crate::email::EmailConfig;
#[cfg(feature = "oauth")]
use crate::oauth::OAuthConfig;
#[cfg(feature = "password")]
use crate::password::PasswordConfig;
use crate::{models::Allow, routes::Routes};

#[derive(Clone)]
pub struct AutheryConfig {
    pub key: String,
    pub allow_signup: Allow,
    pub allow_login: Allow,
    pub https_only: bool,
    pub routes: Routes<String>,
    #[cfg(feature = "password")]
    pub pass: PasswordConfig,
    #[cfg(feature = "email")]
    pub email: EmailConfig,
    #[cfg(feature = "oauth")]
    pub oauth: OAuthConfig,
}

impl AutheryConfig {
    pub fn new(
        key: String,
        routes: impl Into<Routes<String>>,
        #[cfg(feature = "password")] pass: PasswordConfig,
        #[cfg(feature = "email")] email: EmailConfig,
        #[cfg(feature = "oauth")] oauth: OAuthConfig,
    ) -> Self {
        Self {
            key,
            https_only: true,
            allow_signup: Allow::OnSelf,
            allow_login: Allow::OnSelf,
            routes: routes.into(),
            #[cfg(feature = "password")]
            pass,
            #[cfg(feature = "email")]
            email,
            #[cfg(feature = "oauth")]
            oauth,
        }
    }

    pub fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = allow_login;
        self
    }
}

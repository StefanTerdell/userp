use super::{EmailLinkInitError, EmailSignCallbackError};
use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, Intent},
    store::AutheryStore,
};

pub type EmailLoginInitError<StoreError> = EmailLinkInitError<StoreError>;
pub type EmailLoginCallbackError<StoreError> = EmailSignCallbackError<StoreError>;

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Send a login link to the address.
    pub async fn email_login_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailLoginInitError<S::Error>> {
        self.email_sign_init(Intent::LogIn, email, next).await
    }

    /// Verify an emailed login link and log the user in, creating the user
    /// first if signup-on-login is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_login_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), EmailLoginCallbackError<S::Error>> {
        self.email_sign_callback(Intent::LogIn, code).await
    }
}

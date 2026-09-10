use super::{EmailLinkInitError, EmailSignCallbackError};
use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, Intent},
    store::AutheryStore,
};

pub type EmailSignupInitError<StoreError> = EmailLinkInitError<StoreError>;
pub type EmailSignupCallbackError<StoreError> = EmailSignCallbackError<StoreError>;

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Send a signup link to the address.
    pub async fn email_signup_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailSignupInitError<S::Error>> {
        self.email_sign_init(Intent::SignUp, email, next).await
    }

    /// Verify an emailed signup link, create the user, and log them in - or
    /// log in an existing user if login-on-signup is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_signup_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), EmailSignupCallbackError<S::Error>> {
        self.email_sign_callback(Intent::SignUp, code).await
    }
}

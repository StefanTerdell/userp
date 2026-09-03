//! One-time codes over email: instead of a login link, a six-digit code is
//! sent to the address and typed into a form.
//!
//! Codes ride on the email challenge store. The stored challenge code is
//! namespaced as `otp:{address}:{digits}`, which keeps lookups unique per
//! address (two users may well hold the same six digits at once) and keeps a
//! guessed OTP from being replayed against the link-based flows. Verification
//! is rate-limited per address via [`RateLimitOp::OtpAttempt`] on top of the
//! codes being single-use and short-lived - six digits are guessable, so cap
//! attempts tightly in your limiter.

use super::SendEmailChallengeError;
use crate::code_flow::{CodeFlow, CodeInitError, CodeLoginFlow, CodeVerifyError};
use crate::core::CoreAuthery;
use crate::models::{Allow, AutheryCookies, Intent, LoginMethod, email::UserEmail};
use crate::ratelimit::RateLimitOp;
use crate::store::AutheryStore;

pub type OtpInitError<StoreError> = CodeInitError<StoreError, SendEmailChallengeError<StoreError>>;
pub type OtpVerifyError<StoreError> = CodeVerifyError<StoreError>;

/// The email one-time-code channel.
pub(crate) struct EmailOtpFlow;

impl CodeFlow for EmailOtpFlow {
    type SendError<E: std::error::Error> = SendEmailChallengeError<E>;

    fn challenge_key(identifier: &str, code: &str) -> String {
        format!("otp:{identifier}:{code}")
    }

    fn rejected_channel() -> crate::events::CodeChannel {
        crate::events::CodeChannel::EmailOtp
    }

    fn login_method(identifier: String) -> LoginMethod {
        LoginMethod::Otp {
            address: identifier,
        }
    }

    fn send_op(identifier: &str) -> RateLimitOp<'_> {
        RateLimitOp::EmailSend {
            address: identifier,
        }
    }

    fn attempt_op(identifier: &str) -> RateLimitOp<'_> {
        RateLimitOp::OtpAttempt {
            address: identifier,
        }
    }

    fn generator<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> &dyn crate::codes::CodeGenerator {
        &*auth.email.code_generator
    }

    fn challenge_lifetime<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> chrono::Duration {
        auth.email.challenge_lifetime
    }

    async fn deliver<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        to: &str,
        code: &str,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        let content = auth.email.messages.login_code(code);
        auth.send_email(to, &content.subject, content.html_body)
            .await
    }
}

impl CodeLoginFlow for EmailOtpFlow {
    fn offer_login<S: AutheryStore, C: AutheryCookies>(auth: &CoreAuthery<S, C>) -> bool {
        auth.email.offer_otp
    }

    fn allow_login_override<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> Option<&Allow> {
        auth.email.allow_login.as_ref()
    }

    fn allow_signup_override<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> Option<&Allow> {
        auth.email.allow_signup.as_ref()
    }

    async fn lookup_user<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        identifier: &str,
    ) -> Result<Option<(S::User, bool)>, S::Error> {
        Ok(auth
            .store
            .get_user_by_email_address(identifier)
            .await?
            .map(|(user, email)| (user, email.get_allow_link_login())))
    }

    async fn create_user<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        identifier: &str,
    ) -> Result<S::User, S::Error> {
        Ok(auth.store.create_user_by_email_address(identifier).await?.0)
    }
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Send a login code to the address. The generic error message on the
    /// verify side means this deliberately does not reveal whether a user
    /// exists.
    pub async fn otp_login_init(
        &self,
        address: String,
        next: Option<String>,
    ) -> Result<(), OtpInitError<S::Error>> {
        self.code_init::<EmailOtpFlow>(address, next, Intent::LogIn)
            .await
    }

    /// Send a signup code to the address.
    pub async fn otp_signup_init(
        &self,
        address: String,
        next: Option<String>,
    ) -> Result<(), OtpInitError<S::Error>> {
        self.code_init::<EmailOtpFlow>(address, next, Intent::SignUp)
            .await
    }

    /// Verify a login code sent to the address and log the user in,
    /// creating the user first if signup-on-login is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn otp_login_verify(
        self,
        address: &str,
        code: &str,
    ) -> Result<(Self, Option<String>), OtpVerifyError<S::Error>> {
        self.code_verify::<EmailOtpFlow>(address, code, Intent::LogIn)
            .await
    }

    /// Verify a signup code sent to the address, create the user, and log
    /// them in - or log in an existing user if login-on-signup is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn otp_signup_verify(
        self,
        address: &str,
        code: &str,
    ) -> Result<(Self, Option<String>), OtpVerifyError<S::Error>> {
        self.code_verify::<EmailOtpFlow>(address, code, Intent::SignUp)
            .await
    }
}

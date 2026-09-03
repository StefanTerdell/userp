//! Phone-number login via SMS one-time codes.
//!
//! Authery does not pick an SMS vendor: you implement [`SmsSender`] over
//! Twilio, Vonage, a modem, whatever - the trait gets a number and a message
//! body. Everything else mirrors the email `otp` feature: six-digit CSPRNG
//! codes over the shared challenge store, namespaced per number
//! (`sms:{number}:{digits}`), single-use, expiring, and rate-limited on both
//! the send ([`RateLimitOp::SmsSend`] - SMS costs money) and the verify
//! ([`RateLimitOp::SmsAttempt`]).
//!
//! Numbers attached by these flows are verified by construction (the code
//! proved possession). Store numbers in a canonical form (E.164) - authery
//! compares them verbatim.

pub mod providers;

use crate::{
    code_flow::{CodeFlow, CodeInitError, CodeLoginFlow, CodeVerifyError},
    core::CoreAuthery,
    models::{Allow, AutheryCookies, Intent, LoginMethod, sms::UserPhone},
    ratelimit::{RateLimitOp, RateLimited},
    store::AutheryStore,
};
use chrono::Duration;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Boxed error so senders can surface any provider error without authery
/// depending on an error crate.
pub type SmsSendError = Box<dyn std::error::Error + Send + Sync>;

pub type SmsSendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SmsSendError>> + Send + 'a>>;

/// Delivers SMS messages. Implement over your provider of choice and register
/// with [`SmsConfig::new`]. `to` is the number as your store returned or the
/// user entered it; `message` is the full text to deliver.
pub trait SmsSender: std::fmt::Debug + Send + Sync {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a>;
}

/// The copy for the texts authery sends. Each method has an English
/// default; override what you need (branding, language, sender name rules).
pub trait SmsMessages: Send + Sync + std::fmt::Debug {
    /// The one-time login/signup code text.
    fn login_code(&self, code: &str) -> String {
        format!("{code} is your login code. It expires shortly.")
    }

    /// The MFA second-factor code text.
    #[cfg(feature = "mfa")]
    fn mfa_code(&self, code: &str) -> String {
        format!("{code} is your verification code. It expires shortly.")
    }
}

/// The built-in English copy - every [`SmsMessages`] default, unchanged.
#[derive(Debug, Clone, Copy)]
pub struct DefaultSmsMessages;

impl SmsMessages for DefaultSmsMessages {}

#[derive(Debug, Clone)]
pub struct SmsConfig {
    pub sender: Arc<dyn SmsSender>,
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    pub challenge_lifetime: Duration,
    /// Generates the one-time codes for the `sms` flows (and the texted MFA
    /// factor). Defaults to six digits; see [`crate::codes`].
    pub code_generator: Arc<dyn crate::codes::CodeGenerator>,
    /// Composes the texts authery sends; see [`SmsMessages`].
    pub messages: Arc<dyn SmsMessages>,
}

impl SmsConfig {
    pub fn new(sender: impl SmsSender + 'static) -> Self {
        Self {
            sender: Arc::new(sender),
            allow_login: None,
            allow_signup: None,
            challenge_lifetime: Duration::minutes(5),
            code_generator: Arc::new(crate::codes::NumericCode::default()),
            messages: Arc::new(DefaultSmsMessages),
        }
    }

    /// Replace the SMS copy; see [`SmsMessages`].
    pub fn with_messages(mut self, messages: impl SmsMessages + 'static) -> Self {
        self.messages = Arc::new(messages);
        self
    }

    /// Replace the one-time-code generator; see [`crate::codes`].
    pub fn with_code_generator(
        mut self,
        code_generator: impl crate::codes::CodeGenerator + 'static,
    ) -> Self {
        self.code_generator = Arc::new(code_generator);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_challenge_lifetime(mut self, challenge_lifetime: Duration) -> Self {
        self.challenge_lifetime = challenge_lifetime;
        self
    }
}

pub type SmsInitError<StoreError> = CodeInitError<StoreError, SmsSendError>;
pub type SmsVerifyError<StoreError> = CodeVerifyError<StoreError>;

impl crate::ratelimit::MaybeRateLimited for SmsSendError {
    fn rate_limited(&self) -> Option<&RateLimited> {
        None
    }
}

/// The SMS one-time-code channel.
pub(crate) struct SmsFlow;

impl CodeFlow for SmsFlow {
    type SendError<E: std::error::Error> = SmsSendError;

    fn challenge_key(identifier: &str, code: &str) -> String {
        format!("sms:{identifier}:{code}")
    }

    fn rejected_channel() -> crate::events::CodeChannel {
        crate::events::CodeChannel::Sms
    }

    fn login_method(identifier: String) -> LoginMethod {
        LoginMethod::Sms { number: identifier }
    }

    fn send_op(identifier: &str) -> RateLimitOp<'_> {
        RateLimitOp::SmsSend { number: identifier }
    }

    fn attempt_op(identifier: &str) -> RateLimitOp<'_> {
        RateLimitOp::SmsAttempt { number: identifier }
    }

    fn generator<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> &dyn crate::codes::CodeGenerator {
        &*auth.sms.code_generator
    }

    fn challenge_lifetime<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> chrono::Duration {
        auth.sms.challenge_lifetime
    }

    async fn deliver<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        to: &str,
        code: &str,
    ) -> Result<(), SmsSendError> {
        auth.send_sms(to, &auth.sms.messages.login_code(code)).await
    }
}

impl CodeLoginFlow for SmsFlow {
    fn allow_login_override<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> Option<&Allow> {
        auth.sms.allow_login.as_ref()
    }

    fn allow_signup_override<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> Option<&Allow> {
        auth.sms.allow_signup.as_ref()
    }

    async fn lookup_user<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        identifier: &str,
    ) -> Result<Option<(S::User, bool)>, S::Error> {
        Ok(auth
            .store
            .get_user_by_phone(identifier)
            .await?
            .map(|(user, phone)| (user, phone.get_allow_login())))
    }

    async fn create_user<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        identifier: &str,
    ) -> Result<S::User, S::Error> {
        Ok(auth.store.create_user_by_phone(identifier).await?.0)
    }
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Sends through the configured sender, emitting
    /// [`AuthEvent::DeliveryFailed`](crate::events::AuthEvent::DeliveryFailed) on failure.
    pub(crate) async fn send_sms(&self, to: &str, message: &str) -> Result<(), SmsSendError> {
        let result = self.sms.sender.send(to, message).await;

        if let Err(err) = &result {
            self.emit(crate::events::AuthEvent::DeliveryFailed {
                channel: crate::events::DeliveryChannel::Sms,
                recipient: to.to_string(),
                error: format!("{err}: {}", crate::events::source_chain(err.as_ref())),
            });
        }

        result
    }

    /// Send a login code to the number.
    pub async fn sms_login_init(
        &self,
        number: String,
        next: Option<String>,
    ) -> Result<(), SmsInitError<S::Error>> {
        self.code_init::<SmsFlow>(number, next, Intent::LogIn).await
    }

    /// Send a signup code to the number.
    pub async fn sms_signup_init(
        &self,
        number: String,
        next: Option<String>,
    ) -> Result<(), SmsInitError<S::Error>> {
        self.code_init::<SmsFlow>(number, next, Intent::SignUp)
            .await
    }

    /// Verify a login code and log the user in, creating the user first if
    /// signup-on-login is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn sms_login_verify(
        self,
        number: &str,
        code: &str,
    ) -> Result<(Self, Option<String>), SmsVerifyError<S::Error>> {
        self.code_verify::<SmsFlow>(number, code, Intent::LogIn)
            .await
    }

    /// Verify a signup code, create the user, and log them in - or log in an
    /// existing user if login-on-signup is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn sms_signup_verify(
        self,
        number: &str,
        code: &str,
    ) -> Result<(Self, Option<String>), SmsVerifyError<S::Error>> {
        self.code_verify::<SmsFlow>(number, code, Intent::SignUp)
            .await
    }
}

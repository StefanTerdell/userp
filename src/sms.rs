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

use crate::codes::generate_code;
use crate::{
    core::CoreAuthery,
    models::{Allow, AutheryCookies, LoginMethod, User, email::EmailChallenge, sms::UserPhone},
    ratelimit::{RateLimitOp, RateLimited},
    store::AutheryStore,
};
use chrono::{Duration, Utc};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;

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

#[derive(Debug, Clone)]
pub struct SmsConfig {
    pub sender: Arc<dyn SmsSender>,
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    pub challenge_lifetime: Duration,
}

impl SmsConfig {
    pub fn new(sender: impl SmsSender + 'static) -> Self {
        Self {
            sender: Arc::new(sender),
            allow_login: None,
            allow_signup: None,
            challenge_lifetime: Duration::minutes(5),
        }
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

fn challenge_key(number: &str, code: &str) -> String {
    format!("sms:{number}:{code}")
}

#[derive(Debug, Error)]
pub enum SmsInitError<StoreError: std::error::Error> {
    #[error("Sms login not allowed")]
    NotAllowed,
    #[error("Sending failed: {0}")]
    Send(#[from] SmsSendError),
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    Store(StoreError),
}

#[derive(Debug, Error)]
pub enum SmsVerifyError<StoreError: std::error::Error> {
    #[error("Sms login not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error("Sms user not found")]
    NoUser,
    #[error("Wrong or expired code")]
    WrongCode,
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Send a login code to the number.
    pub async fn sms_login_init(
        &self,
        number: String,
        next: Option<String>,
    ) -> Result<(), SmsInitError<S::Error>> {
        if self.sms.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(SmsInitError::NotAllowed);
        }

        self.sms_send_code(number, next).await
    }

    /// Send a signup code to the number.
    pub async fn sms_signup_init(
        &self,
        number: String,
        next: Option<String>,
    ) -> Result<(), SmsInitError<S::Error>> {
        if self.sms.allow_signup.as_ref().unwrap_or(&self.allow_signup) == &Allow::Never {
            return Err(SmsInitError::NotAllowed);
        }

        self.sms_send_code(number, next).await
    }

    async fn sms_send_code(
        &self,
        number: String,
        next: Option<String>,
    ) -> Result<(), SmsInitError<S::Error>> {
        self.rate_limiter
            .check(RateLimitOp::SmsSend { number: &number })
            .await
            .map_err(SmsInitError::RateLimited)?;

        let digits = generate_code();
        let key = challenge_key(&number, &digits);

        let challenge = self
            .store
            .create_challenge(number, key, next, Utc::now() + self.sms.challenge_lifetime)
            .await
            .map_err(SmsInitError::Store)?;

        self.sms
            .sender
            .send(
                challenge.get_address(),
                &format!("{digits} is your login code. It expires shortly."),
            )
            .await?;

        Ok(())
    }

    /// Verify a login code and log the user in, creating the user first if
    /// signup-on-login is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn sms_login_verify(
        self,
        number: &str,
        code: &str,
    ) -> Result<(Self, Option<String>), SmsVerifyError<S::Error>> {
        if self.sms.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(SmsVerifyError::NotAllowed);
        }

        let challenge = self.sms_consume_challenge(number, code).await?;

        let allow_signup =
            self.sms.allow_signup.as_ref().unwrap_or(&self.allow_signup) == &Allow::OnEither;

        let user = match self
            .store
            .get_user_by_phone(challenge.get_address())
            .await?
        {
            Some((user, phone)) if phone.get_allow_login() => Ok(user),
            Some(_) => Err(SmsVerifyError::NotAllowed),
            None if allow_signup => Ok(self
                .store
                .create_user_by_phone(challenge.get_address())
                .await?
                .0),
            None => Err(SmsVerifyError::NoUser),
        }?;

        self.sms_log_in(challenge, user).await
    }

    /// Verify a signup code, create the user, and log them in - or log in an
    /// existing user if login-on-signup is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn sms_signup_verify(
        self,
        number: &str,
        code: &str,
    ) -> Result<(Self, Option<String>), SmsVerifyError<S::Error>> {
        if self.sms.allow_signup.as_ref().unwrap_or(&self.allow_signup) == &Allow::Never {
            return Err(SmsVerifyError::NotAllowed);
        }

        let challenge = self.sms_consume_challenge(number, code).await?;

        let allow_login =
            self.sms.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::OnEither;

        let user = match self
            .store
            .get_user_by_phone(challenge.get_address())
            .await?
        {
            Some((user, phone)) if allow_login && phone.get_allow_login() => Ok(user),
            Some(_) if allow_login => Err(SmsVerifyError::NotAllowed),
            Some(_) => Err(SmsVerifyError::UserExists),
            None => Ok(self
                .store
                .create_user_by_phone(challenge.get_address())
                .await?
                .0),
        }?;

        self.sms_log_in(challenge, user).await
    }

    async fn sms_consume_challenge(
        &self,
        number: &str,
        code: &str,
    ) -> Result<S::EmailChallenge, SmsVerifyError<S::Error>> {
        self.rate_limiter
            .check(RateLimitOp::SmsAttempt { number })
            .await
            .map_err(SmsVerifyError::RateLimited)?;

        let Some(challenge) = self
            .store
            .consume_challenge(challenge_key(number, code))
            .await?
        else {
            return Err(SmsVerifyError::WrongCode);
        };

        if challenge.get_expires() < Utc::now() {
            return Err(SmsVerifyError::WrongCode);
        }

        Ok(challenge)
    }

    async fn sms_log_in(
        self,
        challenge: S::EmailChallenge,
        user: S::User,
    ) -> Result<(Self, Option<String>), SmsVerifyError<S::Error>> {
        Ok((
            self.log_in(
                LoginMethod::Sms {
                    number: challenge.get_address().to_owned(),
                },
                &user.get_id(),
            )
            .await?,
            challenge.get_next().clone(),
        ))
    }
}

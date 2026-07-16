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
use crate::ratelimit::{RateLimitOp, RateLimited};
use crate::{
    core::CoreAuthery,
    models::{
        Allow, AutheryCookies, LoginMethod, User,
        email::{EmailChallenge, UserEmail},
    },
    store::AutheryStore,
};
use chrono::Utc;
use thiserror::Error;
use uuid::Uuid;

/// Generate a six-digit code from the CSPRNG behind UUIDv4. The modulo bias on
/// 122 random bits is on the order of 1e-31 - negligible.
pub(crate) fn generate_code() -> String {
    format!("{:06}", Uuid::new_v4().as_u128() % 1_000_000)
}

fn challenge_key(address: &str, code: &str) -> String {
    format!("otp:{address}:{code}")
}

#[derive(Debug, Error)]
pub enum OtpInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Otp login not allowed")]
    NotAllowed,
}

#[derive(Error, Debug)]
pub enum OtpVerifyError<StoreError: std::error::Error> {
    #[error("Otp login not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error("Otp user not found")]
    NoUser,
    #[error("Wrong or expired code")]
    WrongCode,
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    Store(#[from] StoreError),
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
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(OtpInitError::NotAllowed);
        }

        self.send_otp_code(address, next).await?;

        Ok(())
    }

    /// Send a signup code to the address.
    pub async fn otp_signup_init(
        &self,
        address: String,
        next: Option<String>,
    ) -> Result<(), OtpInitError<S::Error>> {
        if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(OtpInitError::NotAllowed);
        }

        self.send_otp_code(address, next).await?;

        Ok(())
    }

    async fn send_otp_code(
        &self,
        address: String,
        next: Option<String>,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        self.rate_limiter
            .check(RateLimitOp::EmailSend { address: &address })
            .await
            .map_err(SendEmailChallengeError::RateLimited)?;

        let digits = generate_code();
        // Store the code namespaced per address; mail only the digits.
        let key = challenge_key(&address, &digits);

        let challenge = self
            .store
            .email_create_challenge(
                address,
                key,
                next,
                Utc::now() + self.email.challenge_lifetime,
            )
            .await?;

        self.send_email(
            challenge.get_address(),
            "Your login code",
            format!("<p>Your login code is:</p><h1>{digits}</h1><p>It expires shortly. If you did not request it, ignore this email.</p>"),
        )
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
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(OtpVerifyError::NotAllowed);
        }

        let challenge = self.otp_consume_challenge(address, code).await?;

        let allow_signup = self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::OnEither;

        let user = match self
            .store
            .email_get_user_by_email_address(challenge.get_address())
            .await?
        {
            Some((user, email)) if email.get_allow_link_login() => Ok(user),
            Some(_) => Err(OtpVerifyError::NotAllowed),
            None if allow_signup => Ok(self
                .store
                .email_create_user_by_email_address(challenge.get_address())
                .await?
                .0),
            None => Err(OtpVerifyError::NoUser),
        }?;

        self.otp_log_in(challenge, user).await
    }

    /// Verify a signup code sent to the address, create the user, and log
    /// them in - or log in an existing user if login-on-signup is allowed.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn otp_signup_verify(
        self,
        address: &str,
        code: &str,
    ) -> Result<(Self, Option<String>), OtpVerifyError<S::Error>> {
        if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(OtpVerifyError::NotAllowed);
        }

        let challenge = self.otp_consume_challenge(address, code).await?;

        let allow_login =
            self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::OnEither;

        let user = match self
            .store
            .email_get_user_by_email_address(challenge.get_address())
            .await?
        {
            Some((user, email)) if allow_login && email.get_allow_link_login() => Ok(user),
            Some(_) if allow_login => Err(OtpVerifyError::NotAllowed),
            Some(_) => Err(OtpVerifyError::UserExists),
            None => Ok(self
                .store
                .email_create_user_by_email_address(challenge.get_address())
                .await?
                .0),
        }?;

        self.otp_log_in(challenge, user).await
    }

    async fn otp_consume_challenge(
        &self,
        address: &str,
        code: &str,
    ) -> Result<S::EmailChallenge, OtpVerifyError<S::Error>> {
        self.rate_limiter
            .check(RateLimitOp::OtpAttempt { address })
            .await
            .map_err(OtpVerifyError::RateLimited)?;

        let Some(challenge) = self
            .store
            .email_consume_challenge(challenge_key(address, code))
            .await?
        else {
            return Err(OtpVerifyError::WrongCode);
        };

        if challenge.get_expires() < Utc::now() {
            return Err(OtpVerifyError::WrongCode);
        }

        Ok(challenge)
    }

    async fn otp_log_in(
        self,
        challenge: S::EmailChallenge,
        user: S::User,
    ) -> Result<(Self, Option<String>), OtpVerifyError<S::Error>> {
        Ok((
            self.log_in(
                LoginMethod::Otp {
                    address: challenge.get_address().to_owned(),
                },
                &user.get_id(),
            )
            .await?,
            challenge.get_next().clone(),
        ))
    }
}

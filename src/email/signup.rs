use super::{EmailChallenge, SendEmailChallengeError};
use crate::{
    config::Allow,
    core::CoreUserp,
    enums::LoginMethod,
    traits::{User, UserpCookies, UserpStore},
};
use chrono::Utc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailSignupInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Signup not allowed")]
    NotAllowed,
}

#[derive(Error, Debug)]
pub enum EmailSignupError<StoreError: std::error::Error> {
    #[error("Email signup not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum EmailSignupCallbackError<StoreError: std::error::Error> {
    #[error("Email signup not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    EmailSignupError(#[from] EmailSignupError<StoreError>),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
    pub async fn email_signup_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailSignupInitError<S::Error>> {
        if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(EmailSignupInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.routes.actions.signup_email.clone(),
            email,
            "Click here to sign up".into(),
            next,
        )
        .await?;

        Ok(())
    }

    pub async fn email_signup_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), EmailSignupCallbackError<S::Error>> {
        if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(EmailSignupCallbackError::NotAllowed);
        }

        let Some(challenge) = self
            .store
            .email_consume_challenge(code)
            .await
            .map_err(EmailSignupError::Store)?
        else {
            return Err(EmailSignupCallbackError::ChallengeNotFound);
        };

        if challenge.get_expires() < Utc::now() {
            return Err(EmailSignupCallbackError::ChallengeExpired);
        }

        let user = self
            .store
            .email_signup(
                challenge.get_address(),
                self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::OnEither,
            )
            .await?;

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: challenge.get_address().to_owned(),
                },
                user.get_id(),
            )
            .await?,
            challenge.get_next().clone(),
        ))
    }
}

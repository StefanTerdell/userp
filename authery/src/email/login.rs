use super::SendEmailChallengeError;
use crate::{
    core::CoreAuthery,
    models::{
        email::{EmailChallenge, UserEmail},
        User, AutheryCookies,
    },
    store::AutheryStore,
};
use chrono::Utc;
use thiserror::Error;
use crate::models::{Allow, LoginMethod};

#[derive(Error, Debug)]
pub enum EmailLoginError<StoreError: std::error::Error> {
    #[error("Email login not allowed")]
    NotAllowed,
    #[error("Address not verified")]
    NotVerified,
    #[error("Email user not found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum EmailLoginCallbackError<StoreError: std::error::Error> {
    #[error("Email login not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    EmailLoginError(#[from] EmailLoginError<StoreError>),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Error)]
pub enum EmailLoginInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Login not allowed")]
    NotAllowed,
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    pub async fn email_login_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailLoginInitError<S::Error>> {
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(EmailLoginInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.routes.email.login_email.clone(),
            email,
            "Click here to log in".into(),
            next,
        )
        .await?;

        Ok(())
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_login_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), EmailLoginCallbackError<S::Error>> {
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(EmailLoginCallbackError::NotAllowed);
        }

        let Some(challenge) = self
            .store
            .email_consume_challenge(code)
            .await
            .map_err(EmailLoginError::Store)?
        else {
            return Err(EmailLoginCallbackError::ChallengeNotFound);
        };

        if challenge.get_expires() < Utc::now() {
            return Err(EmailLoginCallbackError::ChallengeExpired);
        }

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
            Some(_) => Err(EmailLoginError::NotAllowed),
            None if allow_signup => Ok(self
                .store
                .email_create_user_by_email_address(challenge.get_address())
                .await?
                .0),
            None => Err(EmailLoginError::NoUser),
        }?;

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: challenge.get_address().to_owned(),
                },
                &user.get_id(),
            )
            .await?,
            challenge.get_next().clone(),
        ))
    }
}

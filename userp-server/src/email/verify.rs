use super::SendEmailChallengeError;
use crate::{
    core::CoreUserp,
    models::{email::EmailChallenge, User, UserpCookies},
    store::UserpStore,
};
use chrono::Utc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailVerifyCallbackError<StoreError: std::error::Error> {
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Error)]
pub enum EmailVerifyInitError<StoreError: std::error::Error> {
    #[error("Address not owned by the logged in user")]
    NotAllowed,
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error(transparent)]
    Store(StoreError),
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
    pub async fn email_verify_callback(
        &self,
        code: String,
    ) -> Result<(String, Option<String>), EmailVerifyCallbackError<S::Error>> {
        let Some(challenge) = self.store.email_consume_challenge(code).await? else {
            return Err(EmailVerifyCallbackError::ChallengeNotFound);
        };

        if challenge.get_expires() < Utc::now() {
            return Err(EmailVerifyCallbackError::ChallengeExpired);
        }

        self.store
            .email_set_verified(challenge.get_address())
            .await?;

        Ok((
            challenge.get_address().to_owned(),
            challenge.get_next().clone(),
        ))
    }

    pub async fn email_verify_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailVerifyInitError<S::Error>> {
        // Only the owner may request verification - otherwise anyone logged
        // in could spam arbitrary addresses or verify addresses they added
        // to their own account without controlling them.
        let user = self
            .user()
            .await
            .map_err(EmailVerifyInitError::Store)?
            .ok_or(EmailVerifyInitError::NotAllowed)?;

        let owned = self
            .store
            .email_get_user_by_email_address(&email)
            .await
            .map_err(EmailVerifyInitError::Store)?
            .is_some_and(|(owner, _)| owner.get_id() == user.get_id());

        if !owned {
            return Err(EmailVerifyInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.routes.email.user_email_verify.clone(),
            email,
            "Click here to verify email".into(),
            next,
        )
        .await?;

        Ok(())
    }
}

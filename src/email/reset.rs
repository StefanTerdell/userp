use super::SendEmailChallengeError;
use crate::models::LoginMethod;
use crate::{
    core::CoreAuthery,
    models::{
        AutheryCookies, LoginSession, User,
        email::{EmailChallenge, UserEmail},
    },
    password::PasswordReset,
    store::AutheryStore,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailResetInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Reset not allowed")]
    NotAllowed,
}

impl<E: std::error::Error> crate::ratelimit::MaybeRateLimited for EmailResetInitError<E> {
    fn rate_limited(&self) -> Option<&crate::ratelimit::RateLimited> {
        match self {
            Self::SendingEmail(inner) => inner.rate_limited(),
            Self::NotAllowed => None,
        }
    }
}

#[derive(Error, Debug)]
pub enum EmailResetError<StoreError: std::error::Error> {
    #[error("Email reset not allowed")]
    NotAllowed,
    #[error("Address not verified")]
    NotVerified,
    #[error("Email user not found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Error)]
pub enum EmailResetCallbackError<StoreError: std::error::Error> {
    #[error("Email reset not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired { address: String },
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    EmailResetError(#[from] EmailResetError<StoreError>),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<E: std::error::Error> From<crate::email::EmailChallengeError<E>>
    for EmailResetCallbackError<E>
{
    fn from(err: crate::email::EmailChallengeError<E>) -> Self {
        match err {
            crate::email::EmailChallengeError::Expired { address } => {
                Self::ChallengeExpired { address }
            }
            crate::email::EmailChallengeError::NotFound => Self::ChallengeNotFound,
            crate::email::EmailChallengeError::Store(inner) => Self::Store(inner),
        }
    }
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    pub async fn email_reset_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailResetInitError<S::Error>> {
        if self.pass.allow_reset == PasswordReset::Never {
            return Err(EmailResetInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.routes.email.password_reset_callback.clone(),
            email,
            crate::email::EmailLinkKind::Reset,
            next,
        )
        .await?;

        Ok(())
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_reset_callback(
        self,
        code: String,
    ) -> Result<Self, EmailResetCallbackError<S::Error>> {
        use crate::password::PasswordReset;

        if self.pass.allow_reset == PasswordReset::Never {
            return Err(EmailResetCallbackError::NotAllowed);
        }

        let challenge = self.consume_email_challenge(code).await?;

        let user = match self
            .store
            .get_user_by_email_address(challenge.get_address())
            .await?
        {
            Some((user, email))
                if self.pass.allow_reset == PasswordReset::AnyUserEmail || email.get_verified() =>
            {
                Ok(user)
            }
            Some(_) => Err(EmailResetError::NotVerified),
            None => Err(EmailResetError::NoUser),
        }?;

        Ok(self
            .log_in(
                LoginMethod::PasswordReset {
                    address: challenge.get_address().to_owned(),
                },
                &user.get_id(),
            )
            .await?)
    }

    pub async fn is_reset_session(&self) -> Result<bool, S::Error> {
        Ok(self.reset_session().await?.is_some())
    }

    pub async fn reset_session(&self) -> Result<Option<S::LoginSession>, S::Error> {
        self.session_matching(|s| matches!(s.get_method(), LoginMethod::PasswordReset { .. }))
            .await
    }

    pub async fn reset_user_session(&self) -> Result<Option<(S::User, S::LoginSession)>, S::Error> {
        let Some(session) = self.reset_session().await? else {
            return Ok(None);
        };

        Ok(self
            .store
            .get_user(&session.get_user_id())
            .await?
            .map(|user| (user, session)))
    }

    pub async fn reset_user(&self) -> Result<Option<S::User>, S::Error> {
        Ok(self.reset_user_session().await?.map(|(user, _)| user))
    }
}

use super::provider::OAuthProvider;
use super::{Allow, AutheryStore, CoreAuthery, OAuthCallbackError, OAuthFlow};
use crate::models::LoginMethod;
use crate::models::{
    AutheryCookies, User,
    oauth::{OAuthToken, UnmatchedOAuthToken},
};
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum OAuthLoginCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error("User doesn't exists")]
    NoUser,
    #[error(transparent)]
    Store(StoreError),
}

#[derive(Debug, Error)]
pub enum OAuthLoginInitError {
    #[error("Login not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    pub fn oauth_login_providers(&self) -> Vec<&Arc<dyn OAuthProvider>> {
        self.oauth
            .providers
            .0
            .iter()
            .filter(|provider| {
                self.login_allow(
                    provider
                        .allow_login()
                        .as_ref()
                        .or(self.oauth.allow_login.as_ref()),
                ) != &Allow::Never
            })
            .collect()
    }

    pub async fn oauth_login_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthLoginInitError> {
        let provider = self
            .oauth
            .providers
            .get(&provider_name)
            .cloned()
            .ok_or(OAuthLoginInitError::ProviderNotFound(provider_name.clone()))?;

        if self.login_allow(
            provider
                .allow_login()
                .as_ref()
                .or(self.oauth.allow_login.as_ref()),
        ) == &Allow::Never
        {
            return Err(OAuthLoginInitError::NotAllowed);
        };

        Ok(self
            .oauth_init(
                provider,
                OAuthFlow::LogIn {
                    next,
                    context: None,
                },
            )
            .await)
    }

    /// Begin a login through a dynamically resolved provider. `context` is an
    /// opaque, app-chosen string (e.g. a tenant or org id) handed to the
    /// configured [`crate::oauth::OAuthProviderResolver`] here and again at
    /// the callback; the store receives it on the resulting token as
    /// [`UnmatchedOAuthToken::context`].
    pub async fn oauth_login_init_with_context(
        self,
        context: String,
        provider_name: &str,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthLoginInitError> {
        let provider = self
            .oauth_resolve_provider(Some(&context), provider_name)
            .await
            .map_err(|_| OAuthLoginInitError::ProviderNotFound(provider_name.to_string()))?;

        if self.login_allow(
            provider
                .allow_login()
                .as_ref()
                .or(self.oauth.allow_login.as_ref()),
        ) == &Allow::Never
        {
            return Err(OAuthLoginInitError::NotAllowed);
        };

        Ok(self
            .oauth_init(
                provider,
                OAuthFlow::LogIn {
                    next,
                    context: Some(context),
                },
            )
            .await)
    }

    pub(crate) async fn oauth_login_callback_inner(
        self,
        provider: Arc<dyn OAuthProvider>,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError<S::Error>> {
        let OAuthFlow::LogIn { next, .. } = flow else {
            return Err(OAuthLoginCallbackError::UnexpectedFlow(flow));
        };

        let allow_signup = self.signup_allow(
            provider
                .allow_signup()
                .as_ref()
                .or(self.oauth.allow_signup.as_ref()),
        ) == &Allow::OnEither;

        let (user, token) = match self
            .store
            .get_user_by_unmatched_token(unmatched_token.clone())
            .await
            .map_err(OAuthLoginCallbackError::Store)?
        {
            Some(user_token) => Ok(user_token),
            None if allow_signup => Ok(self
                .store
                .create_user_from_unmatched_token(unmatched_token)
                .await
                .map_err(OAuthLoginCallbackError::Store)?),
            None => Err(OAuthLoginCallbackError::NoUser),
        }?;

        Ok((
            self.log_in(
                LoginMethod::OAuth {
                    token_id: token.get_id().to_string(),
                },
                &user.get_id(),
            )
            .await
            .map_err(OAuthLoginCallbackError::Store)?,
            next,
        ))
    }
}

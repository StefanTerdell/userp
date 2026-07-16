use super::provider::OAuthProvider;
use super::{Allow, CoreAuthery, OAuthCallbackError, OAuthFlow, AutheryStore};
use crate::models::{
    oauth::{OAuthToken, UnmatchedOAuthToken},
    User, AutheryCookies,
};
use oauth2::{AuthorizationCode, CsrfToken};
use std::sync::Arc;
use thiserror::Error;
use url::Url;
use crate::models::LoginMethod;

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
                provider
                    .allow_login()
                    .as_ref()
                    .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
                    != &Allow::Never
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

        if provider
            .allow_login()
            .as_ref()
            .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
            == &Allow::Never
        {
            return Err(OAuthLoginInitError::NotAllowed);
        };

        let path = self.routes.oauth.callbacks.login_oauth_provider.clone();

        Ok(self
            .oauth_init(path, provider, OAuthFlow::LogIn { next })
            .await)
    }

    pub(crate) async fn oauth_login_callback_inner(
        self,
        provider: Arc<dyn OAuthProvider>,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError<S::Error>> {
        let OAuthFlow::LogIn { next } = flow else {
            return Err(OAuthLoginCallbackError::UnexpectedFlow(flow));
        };

        let allow_signup = provider.allow_signup().as_ref().unwrap_or(
            self.oauth
                .allow_signup
                .as_ref()
                .unwrap_or(&self.allow_signup),
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

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_login_callback(
        mut self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError<S::Error>> {
        let (unmatched_token, flow, provider) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.routes.oauth.callbacks.login_oauth_provider.clone(),
            )
            .await?;

        #[cfg(feature = "organizations")]
        if matches!(flow, OAuthFlow::OrgLogIn { .. }) {
            return self
                .org_oauth_login_callback_inner(unmatched_token, flow)
                .await;
        }

        self.oauth_login_callback_inner(provider, unmatched_token, flow)
            .await
    }
}

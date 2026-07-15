use super::{provider::OAuthProvider, CoreUserp, OAuthCallbackError, OAuthFlow, UserpStore};
use crate::models::{
    oauth::{OAuthToken, UnmatchedOAuthToken},
    User, UserpCookies,
};
use oauth2::{AuthorizationCode, CsrfToken};
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum OAuthLinkInitError<StoreError: std::error::Error> {
    #[error("Linking not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
    #[error("No user found or not logged in")]
    NoUser,
    #[error(transparent)]
    Store(StoreError),
}

#[derive(Error, Debug)]
pub enum OAuthLinkCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Linking not allowed")]
    NotAllowed,
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error("OAuth account already in use")]
    UserConflict,
    #[error(transparent)]
    Store(StoreError),
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
    pub fn oauth_link_providers(&self) -> Vec<&Arc<dyn OAuthProvider>> {
        self.oauth
            .providers
            .0
            .iter()
            .filter(|provider| provider.allow_linking().unwrap_or(self.oauth.allow_linking))
            .collect()
    }

    pub async fn oauth_link_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthLinkInitError<S::Error>> {
        let user = self
            .user()
            .await
            .map_err(OAuthLinkInitError::Store)?
            .ok_or(OAuthLinkInitError::NoUser)?;

        let provider = self
            .oauth
            .providers
            .get(&provider_name)
            .cloned()
            .ok_or(OAuthLinkInitError::ProviderNotFound(provider_name.clone()))?;

        if !provider
            .allow_linking()
            .as_ref()
            .unwrap_or(&self.oauth.allow_linking)
        {
            return Err(OAuthLinkInitError::NotAllowed);
        };

        let path = self.routes.oauth.callbacks.user_oauth_link_provider.clone();

        Ok(self
            .oauth_init(
                path,
                provider,
                OAuthFlow::Link {
                    next,
                    user_id: user.get_id(),
                },
            )
            .await)
    }

    pub(crate) async fn oauth_link_callback_inner(
        &self,
        provider: Arc<dyn OAuthProvider>,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<Option<String>, OAuthLinkCallbackError<S::Error>> {
        let OAuthFlow::Link { user_id, next } = flow else {
            return Err(OAuthLinkCallbackError::UnexpectedFlow(flow));
        };

        if provider.allow_linking().is_some_and(|l| !l) {
            return Err(OAuthLinkCallbackError::NotAllowed);
        }

        match self
            .store
            .get_token_by_unmatched_token(unmatched_token.clone())
            .await
            .map_err(OAuthLinkCallbackError::Store)?
        {
            Some(token) if token.get_user_id() == user_id => Ok(token),
            Some(_) => Err(OAuthLinkCallbackError::UserConflict),
            None => Ok(self
                .store
                .create_user_token_from_unmatched_token(user_id, unmatched_token)
                .await
                .map_err(OAuthLinkCallbackError::Store)?),
        }?;

        Ok(next)
    }

    pub async fn oauth_link_callback(
        &mut self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<Option<String>, OAuthLinkCallbackError<S::Error>> {
        let (unmatched_token, flow, provider) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.routes.oauth.callbacks.user_oauth_link_provider.clone(),
            )
            .await?;

        self.oauth_link_callback_inner(provider, unmatched_token, flow)
            .await
    }
}

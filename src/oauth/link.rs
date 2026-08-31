use super::{AutheryStore, CoreAuthery, OAuthCallbackError, OAuthFlow, provider::OAuthProvider};
use crate::models::{
    AutheryCookies, User,
    oauth::{OAuthToken, UnmatchedOAuthToken},
};
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
    #[error("Expected a link flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error("Misformed user id in flow data")]
    MisformedId,
    #[error("OAuth account already in use")]
    UserConflict,
    #[error(transparent)]
    Store(StoreError),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
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

        Ok(self
            .oauth_init(
                provider,
                OAuthFlow::Link {
                    next,
                    user_id: user.get_id().to_string(),
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

        let Ok(user_id) = user_id.parse::<S::UserId>() else {
            return Err(OAuthLinkCallbackError::MisformedId);
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
                .create_user_token_from_unmatched_token(&user_id, unmatched_token)
                .await
                .map_err(OAuthLinkCallbackError::Store)?),
        }?;

        Ok(next)
    }
}

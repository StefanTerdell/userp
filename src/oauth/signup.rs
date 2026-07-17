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
pub enum OAuthSignupCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Expected a signup flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error("User already exists")]
    UserExists,
    #[error(transparent)]
    Store(StoreError),
}

#[derive(Debug, Error)]
pub enum OAuthSignupInitError {
    #[error("Signup not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    pub fn oauth_signup_providers(&self) -> Vec<&Arc<dyn OAuthProvider>> {
        self.oauth
            .providers
            .0
            .iter()
            .filter(|provider| {
                provider.allow_signup().as_ref().unwrap_or(
                    self.oauth
                        .allow_signup
                        .as_ref()
                        .unwrap_or(&self.allow_signup),
                ) != &Allow::Never
            })
            .collect()
    }

    pub async fn oauth_signup_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthSignupInitError> {
        let provider = self.oauth.providers.get(&provider_name).cloned().ok_or(
            OAuthSignupInitError::ProviderNotFound(provider_name.clone()),
        )?;

        if provider.allow_signup().as_ref().unwrap_or(
            self.oauth
                .allow_signup
                .as_ref()
                .unwrap_or(&self.allow_signup),
        ) == &Allow::Never
        {
            return Err(OAuthSignupInitError::NotAllowed);
        };

        Ok(self
            .oauth_init(
                provider,
                OAuthFlow::SignUp {
                    next,
                    context: None,
                },
            )
            .await)
    }

    /// Begin a signup through a dynamically resolved provider. See
    /// [`CoreAuthery::oauth_login_init_with_context`].
    pub async fn oauth_signup_init_with_context(
        self,
        context: String,
        provider_name: &str,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthSignupInitError> {
        let provider = self
            .oauth_resolve_provider(Some(&context), provider_name)
            .await
            .map_err(|_| OAuthSignupInitError::ProviderNotFound(provider_name.to_string()))?;

        if provider.allow_signup().as_ref().unwrap_or(
            self.oauth
                .allow_signup
                .as_ref()
                .unwrap_or(&self.allow_signup),
        ) == &Allow::Never
        {
            return Err(OAuthSignupInitError::NotAllowed);
        };

        Ok(self
            .oauth_init(
                provider,
                OAuthFlow::SignUp {
                    next,
                    context: Some(context),
                },
            )
            .await)
    }

    pub(crate) async fn oauth_signup_callback_inner(
        self,
        provider: Arc<dyn OAuthProvider>,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthSignupCallbackError<S::Error>> {
        let OAuthFlow::SignUp { next, .. } = flow else {
            return Err(OAuthSignupCallbackError::UnexpectedFlow(flow));
        };

        let allow_login = provider
            .allow_login()
            .as_ref()
            .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
            == &Allow::OnEither;

        let (user, token) = match self
            .store
            .get_user_by_unmatched_token(unmatched_token.clone())
            .await
            .map_err(OAuthSignupCallbackError::Store)?
        {
            Some(user_token) if allow_login => Ok(user_token),
            Some(_) => Err(OAuthSignupCallbackError::UserExists),
            None => Ok(self
                .store
                .create_user_from_unmatched_token(unmatched_token)
                .await
                .map_err(OAuthSignupCallbackError::Store)?),
        }?;

        Ok((
            self.log_in(
                LoginMethod::OAuth {
                    token_id: token.get_id().to_string(),
                },
                &user.get_id(),
            )
            .await
            .map_err(OAuthSignupCallbackError::Store)?,
            next,
        ))
    }
}

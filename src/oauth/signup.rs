use super::provider::OAuthProvider;
use super::{
    Allow, CoreUserp, OAuthCallbackError, OAuthFlow, OAuthToken, UnmatchedOAuthToken, UserpStore,
};
use crate::enums::LoginMethod;
use crate::traits::{User, UserpCookies};
use oauth2::{AuthorizationCode, CsrfToken};
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum OAuthSignupCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Expected a signup flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error(transparent)]
    SignupError(#[from] OAuthSignupError<StoreError>),
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

#[derive(Error, Debug)]
pub enum OAuthSignupError<StoreError: std::error::Error> {
    #[error("OAuth signup not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
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

        let path = self.routes.actions.signup_oauth_provider.clone();

        Ok(self
            .oauth_init(path, provider, OAuthFlow::SignUp { next })
            .await)
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_signup_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthSignupCallbackError<S::Error>> {
        let (unmatched_token, flow, provider) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.routes.actions.signup_oauth_provider.clone(),
            )
            .await?;

        self.oauth_signup_callback_inner(provider, unmatched_token, flow)
            .await
    }

    pub(crate) async fn oauth_signup_callback_inner(
        self,
        provider: Arc<dyn OAuthProvider>,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthSignupCallbackError<S::Error>> {
        let OAuthFlow::SignUp { next } = flow else {
            return Err(OAuthSignupCallbackError::UnexpectedFlow(flow));
        };

        let (user, token) = self
            .store
            .oauth_signup(
                unmatched_token,
                provider
                    .allow_login()
                    .as_ref()
                    .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
                    == &Allow::OnEither,
            )
            .await?;

        Ok((
            self.log_in(
                LoginMethod::OAuth {
                    token_id: token.get_id(),
                },
                user.get_id(),
            )
            .await
            .map_err(OAuthSignupCallbackError::Store)?,
            next,
        ))
    }
}

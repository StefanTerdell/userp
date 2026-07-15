pub mod client;
pub mod link;
pub mod login;
pub mod provider;
pub mod refresh;
pub mod signup;

use crate::{
    core::CoreUserp,
    models::{
        oauth::{OAuthProviderUser, UnmatchedOAuthToken},
        UserpCookies,
    },
    store::UserpStore,
};
use userp_client::models::Allow;

use self::link::OAuthLinkCallbackError;
use self::login::OAuthLoginCallbackError;
use self::provider::OAuthProvider;
use self::refresh::OAuthRefreshCallbackError;
use self::signup::OAuthSignupCallbackError;

use chrono::Utc;
use oauth2::ExtraTokenFields;
use oauth2::{basic::BasicTokenType, StandardTokenResponse};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeVerifier, RedirectUrl, TokenResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt::Display, sync::Arc};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

const OAUTH_DATA_KEY: &str = "userp-oauth-state";

pub enum RefreshInitResult {
    Redirect(Url),
    Ok,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OAuthFlow {
    LogIn {
        next: Option<String>,
    },
    SignUp {
        next: Option<String>,
    },
    Link {
        user_id: Uuid,
        next: Option<String>,
    },
    Refresh {
        token_id: Uuid,
        next: Option<String>,
    },
}

impl Display for OAuthFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OAuthFlow::LogIn { .. } => "LogIn",
            OAuthFlow::SignUp { .. } => "SignUp",
            OAuthFlow::Link { .. } => "Link",
            OAuthFlow::Refresh { .. } => "Refresh",
        })
    }
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    pub allow_linking: bool,
    pub base_url: Url,
    pub providers: OAuthProviders,
}

impl OAuthConfig {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            allow_login: None,
            allow_signup: None,
            allow_linking: true,
            providers: Default::default(),
        }
    }

    pub fn with_client(mut self, client: impl OAuthProvider + 'static) -> Self {
        self.providers.0.push(Arc::new(client));
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    pub fn with_allow_linking(mut self, allow_linking: bool) -> Self {
        self.allow_linking = allow_linking;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct OAuthProviders(pub(super) Vec<Arc<dyn OAuthProvider>>);

impl OAuthProviders {
    pub fn get(&self, name: &str) -> Option<&Arc<dyn OAuthProvider>> {
        self.0.iter().find(|c| c.name() == name)
    }
}

impl UnmatchedOAuthToken {
    pub fn from_standard_token_response<T: ExtraTokenFields>(
        token_response: &StandardTokenResponse<T, BasicTokenType>,
        provider_name: &str,
        provider_user: OAuthProviderUser,
    ) -> Self {
        Self {
            access_token: token_response.access_token().secret().into(),
            refresh_token: token_response.refresh_token().map(|rt| rt.secret().into()),
            expires: token_response.expires_in().map(|d| Utc::now() + d),
            scopes: token_response
                .scopes()
                .map(|scopes| scopes.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
            provider_name: provider_name.into(),
            provider_user_id: provider_user.id,
            provider_user_raw: provider_user.raw,
        }
    }
}

#[derive(Error, Debug)]
pub enum OAuthCallbackError {
    #[error("No provider found with name: '{0}'")]
    NoProvider(String),
    #[error("No oauth flow & state data cookie found")]
    NoOAuthDataCookie,
    #[error("Misformed OAuthData: {0}")]
    MisformedOAuthData(#[from] serde_json::Error),
    #[error("CSRF tokens didn't match")]
    CsrfMismatch,
    #[error(transparent)]
    ExchangeAuthorizationCodeError(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum OAuthGenericCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    Callback(#[from] OAuthCallbackError),
    #[error(transparent)]
    Signup(#[from] OAuthSignupCallbackError<StoreError>),
    #[error(transparent)]
    Login(#[from] OAuthLoginCallbackError<StoreError>),
    #[error(transparent)]
    Link(#[from] OAuthLinkCallbackError<StoreError>),
    #[error(transparent)]
    Refresh(#[from] OAuthRefreshCallbackError<StoreError>),
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
    fn redirect_uri(&self, path: String, provider_name: &str) -> RedirectUrl {
        let path = if path.ends_with('/') {
            path
        } else {
            format!("{path}/")
        };

        let path = path.replace(":provider", provider_name);

        RedirectUrl::from_url(self.oauth.base_url.join(path.as_str()).unwrap())
    }

    async fn oauth_init(
        mut self,
        path: String,
        provider: Arc<dyn OAuthProvider>,
        oauth_flow: OAuthFlow,
    ) -> (Self, Url) {
        let (auth_url, csrf_state, pkce_verifier) = provider.get_authorization_url_and_state(
            &self.redirect_uri(path, provider.name()),
            provider.scopes(),
        );

        self.cookies.add(
            OAUTH_DATA_KEY,
            &json!((csrf_state, pkce_verifier.secret(), oauth_flow)).to_string(),
        );

        (self, auth_url)
    }

    async fn oauth_callback_inner(
        &mut self,
        provider_name: String,
        code: AuthorizationCode,
        csrf_token: CsrfToken,
        path: String,
    ) -> Result<(UnmatchedOAuthToken, OAuthFlow, Arc<dyn OAuthProvider>), OAuthCallbackError> {
        let provider = self
            .oauth
            .providers
            .get(&provider_name)
            .ok_or(OAuthCallbackError::NoProvider(provider_name.clone()))?
            .clone();

        let oauth_data = self
            .cookies
            .get(OAUTH_DATA_KEY)
            .ok_or(OAuthCallbackError::NoOAuthDataCookie)?;

        // The state cookie is single-use.
        self.cookies.remove(OAUTH_DATA_KEY);

        let (prev_csrf_token, pkce_verifier, oauth_flow) =
            serde_json::from_str::<(CsrfToken, String, OAuthFlow)>(&oauth_data)?;

        if csrf_token.secret() != prev_csrf_token.secret() {
            return Err(OAuthCallbackError::CsrfMismatch);
        }

        let unmatched_token = provider
            .exchange_authorization_code(
                provider.name(),
                &self.redirect_uri(path, &provider_name),
                &code,
                Some(PkceCodeVerifier::new(pkce_verifier)),
            )
            .await?;

        Ok((unmatched_token, oauth_flow, provider))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_generic_callback(
        mut self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthGenericCallbackError<S::Error>> {
        let (unmatched_token, flow, provider) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.routes.oauth.callbacks.signup_oauth_provider.clone(),
            )
            .await?;

        Ok(match &flow {
            OAuthFlow::LogIn { .. } => {
                self.oauth_login_callback_inner(provider, unmatched_token, flow)
                    .await?
            }
            OAuthFlow::SignUp { .. } => {
                self.oauth_signup_callback_inner(provider, unmatched_token, flow)
                    .await?
            }
            OAuthFlow::Link { .. } => {
                let next = self
                    .oauth_link_callback_inner(provider, unmatched_token, flow)
                    .await?;

                (self, next)
            }
            OAuthFlow::Refresh { .. } => {
                let next = self
                    .oauth_refresh_callback_inner(unmatched_token, flow)
                    .await?;

                (self, next)
            }
        })
    }
}

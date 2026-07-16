pub mod client;
pub mod link;
pub mod login;
pub mod provider;
pub mod refresh;
pub mod signup;

use crate::{
    core::CoreAuthery,
    models::{
        oauth::{OAuthProviderUser, UnmatchedOAuthToken},
        AutheryCookies,
    },
    store::AutheryStore,
};
use crate::models::Allow;

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

const OAUTH_DATA_KEY: &str = "authery-oauth-state";

pub enum RefreshInitResult {
    Redirect(Url),
    Ok,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OAuthFlow {
    LogIn {
        next: Option<String>,
    },
    #[cfg(feature = "organizations")]
    /// A login through an org-attached OIDC provider. The provider is
    /// resolved from the store at callback time using the org id (in its
    /// string representation).
    OrgLogIn {
        org_id: String,
        next: Option<String>,
    },
    SignUp {
        next: Option<String>,
    },
    Link {
        /// The linking user's ID, in its string representation
        user_id: String,
        next: Option<String>,
    },
    Refresh {
        /// The refreshed token's ID, in its string representation
        token_id: String,
        next: Option<String>,
    },
}

impl Display for OAuthFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OAuthFlow::LogIn { .. } => "LogIn",
            #[cfg(feature = "organizations")]
            OAuthFlow::OrgLogIn { .. } => "OrgLogIn",
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
        self.providers.push(Arc::new(client));
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

/// The configured OAuth providers. Wrapped in a single `Arc` so cloning the
/// config (which happens once per request) is one refcount bump rather than a
/// per-provider allocation.
#[derive(Debug, Clone, Default)]
pub struct OAuthProviders(pub(super) Arc<Vec<Arc<dyn OAuthProvider>>>);

impl OAuthProviders {
    pub(super) fn push(&mut self, provider: Arc<dyn OAuthProvider>) {
        Arc::make_mut(&mut self.0).push(provider);
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn OAuthProvider>> {
        self.0.iter().find(|c| c.name() == name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn OAuthProvider>> {
        self.0.iter()
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
    /// Resolving an org-attached provider failed in the store. Stringified
    /// because this error predates the store's error type in the signature.
    #[cfg(feature = "organizations")]
    #[error("Org provider lookup failed: {0}")]
    OrgProviderLookup(String),
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

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    fn redirect_uri(&self, path: String, provider_name: &str) -> RedirectUrl {
        let path = if path.ends_with('/') {
            path
        } else {
            format!("{path}/")
        };

        let path = path.replace("{provider}", provider_name);

        RedirectUrl::from_url(self.oauth.base_url.join(path.as_str()).unwrap())
    }

    pub(crate) async fn oauth_init(
        mut self,
        path: String,
        provider: Arc<dyn OAuthProvider>,
        oauth_flow: OAuthFlow,
    ) -> (Self, Url) {
        let (auth_url, csrf_state, pkce_verifier, nonce) = provider
            .get_authorization_url_and_state(
                &self.redirect_uri(path, provider.name()),
                provider.scopes(),
            );

        self.cookies.add(
            OAUTH_DATA_KEY,
            &json!((csrf_state, pkce_verifier.secret(), nonce, oauth_flow)).to_string(),
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
        let oauth_data = self
            .cookies
            .get(OAUTH_DATA_KEY)
            .ok_or(OAuthCallbackError::NoOAuthDataCookie)?;

        // The state cookie is single-use.
        self.cookies.remove(OAUTH_DATA_KEY);

        let (prev_csrf_token, pkce_verifier, nonce, oauth_flow) =
            serde_json::from_str::<(CsrfToken, String, Option<String>, OAuthFlow)>(&oauth_data)?;

        if csrf_token.secret() != prev_csrf_token.secret() {
            return Err(OAuthCallbackError::CsrfMismatch);
        }

        // Org flows resolve the provider from the store; everything else uses
        // the statically configured providers.
        let provider = match &oauth_flow {
            #[cfg(feature = "organizations")]
            OAuthFlow::OrgLogIn { org_id, .. } => {
                self.org_oauth_provider(org_id, &provider_name).await?
            }
            _ => self
                .oauth
                .providers
                .get(&provider_name)
                .ok_or(OAuthCallbackError::NoProvider(provider_name.clone()))?
                .clone(),
        };

        let unmatched_token = provider
            .exchange_authorization_code(
                provider.name(),
                &self.redirect_uri(path, &provider_name),
                &code,
                Some(PkceCodeVerifier::new(pkce_verifier)),
                nonce,
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
            #[cfg(feature = "organizations")]
            OAuthFlow::OrgLogIn { .. } => {
                self.org_oauth_login_callback_inner(unmatched_token, flow)
                    .await
                    .map_err(OAuthGenericCallbackError::Login)?
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

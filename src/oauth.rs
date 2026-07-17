pub mod client;
pub mod link;
pub mod login;
pub mod provider;
pub mod refresh;
pub mod signup;

use crate::models::Allow;
use crate::{
    core::CoreAuthery,
    models::{
        AutheryCookies,
        oauth::{OAuthProviderUser, UnmatchedOAuthToken},
    },
    store::AutheryStore,
};

use self::link::OAuthLinkCallbackError;
use self::login::OAuthLoginCallbackError;
use self::provider::OAuthProvider;
use self::refresh::OAuthRefreshCallbackError;
use self::signup::OAuthSignupCallbackError;

use chrono::Utc;
use oauth2::ExtraTokenFields;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeVerifier, RedirectUrl, TokenResponse};
use oauth2::{StandardTokenResponse, basic::BasicTokenType};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt::Display, future::Future, pin::Pin, sync::Arc};
use thiserror::Error;
use url::Url;

const OAUTH_DATA_KEY: &str = "authery-oauth-state";

/// The flow cookie is keyed by the CSRF state so concurrent flows (two login
/// tabs, a login and a link) don't clobber each other; the callback knows
/// which cookie to open because the state comes back as a query param. The
/// value is encrypted+authenticated by the private jar, so a forged state can
/// at most fail to find a cookie.
fn oauth_data_key(csrf_state: &str) -> String {
    format!("{OAUTH_DATA_KEY}-{csrf_state}")
}

pub enum RefreshInitResult {
    Redirect(Url),
    Ok,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OAuthFlow {
    LogIn {
        next: Option<String>,
        /// App-chosen context for dynamically resolved providers; see
        /// [`OAuthProviderResolver`]. `None` for statically configured ones.
        context: Option<String>,
    },
    SignUp {
        next: Option<String>,
        /// See [`OAuthFlow::LogIn::context`].
        context: Option<String>,
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

impl OAuthFlow {
    /// The provider-resolution context this flow was started with, if any.
    pub fn context(&self) -> Option<&str> {
        match self {
            OAuthFlow::LogIn { context, .. } | OAuthFlow::SignUp { context, .. } => {
                context.as_deref()
            }
            _ => None,
        }
    }
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
    /// Resolves providers at request time for context-carrying flows; see
    /// [`OAuthProviderResolver`].
    pub provider_resolver: Option<Arc<dyn OAuthProviderResolver>>,
}

impl OAuthConfig {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            allow_login: None,
            allow_signup: None,
            allow_linking: true,
            providers: Default::default(),
            provider_resolver: None,
        }
    }

    pub fn with_client(mut self, client: impl OAuthProvider + 'static) -> Self {
        self.providers.push(Arc::new(client));
        self
    }

    /// Install a [`OAuthProviderResolver`] for dynamically resolved (e.g.
    /// per-tenant) providers.
    pub fn with_provider_resolver(
        mut self,
        resolver: impl OAuthProviderResolver + 'static,
    ) -> Self {
        self.provider_resolver = Some(Arc::new(resolver));
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
            context: None,
        }
    }
}

/// Resolves OAuth/OIDC providers at request time instead of from the list
/// configured at startup. Register with
/// [`OAuthConfig::with_provider_resolver`]; flows started through
/// [`CoreAuthery::oauth_login_init_with_context`] (or the signup variant)
/// carry an opaque, app-chosen `context` string through the encrypted state
/// cookie, and both the init and the callback resolve the provider through
/// this hook.
///
/// This is the primitive for multi-tenant setups: the resolver typically
/// captures the app's own database handle and builds an
/// [`provider::oidc::OAuthOidcProvider`] from a per-tenant table keyed by
/// `context`. Returning `None` fails the flow with
/// [`OAuthCallbackError::NoProvider`].
pub trait OAuthProviderResolver: std::fmt::Debug + Send + Sync {
    fn resolve<'a>(
        &'a self,
        context: &'a str,
        provider_name: &'a str,
    ) -> ProviderResolverFuture<'a>;
}

pub type ProviderResolverFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Option<Arc<dyn OAuthProvider>>, anyhow::Error>> + Send + 'a>,
>;

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
    #[error("The flow carries a provider context but no provider resolver is configured")]
    NoProviderResolver,
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
    pub(crate) fn redirect_uri(&self) -> RedirectUrl {
        RedirectUrl::from_url(
            self.oauth
                .base_url
                .join(self.routes.oauth.callback.as_str())
                .unwrap(),
        )
    }

    pub(crate) async fn oauth_init(
        mut self,
        provider: Arc<dyn OAuthProvider>,
        oauth_flow: OAuthFlow,
    ) -> (Self, Url) {
        let (auth_url, csrf_state, pkce_verifier, nonce) =
            provider.get_authorization_url_and_state(&self.redirect_uri(), provider.scopes());

        self.cookies.add(
            &oauth_data_key(csrf_state.secret()),
            &json!((
                csrf_state,
                pkce_verifier.secret(),
                nonce,
                provider.name(),
                oauth_flow
            ))
            .to_string(),
        );

        (self, auth_url)
    }

    async fn oauth_callback_inner(
        &mut self,
        code: AuthorizationCode,
        csrf_token: CsrfToken,
    ) -> Result<(UnmatchedOAuthToken, OAuthFlow, Arc<dyn OAuthProvider>), OAuthCallbackError> {
        let data_key = oauth_data_key(csrf_token.secret());
        let oauth_data = self
            .cookies
            .get(&data_key)
            .ok_or(OAuthCallbackError::NoOAuthDataCookie)?;

        // The state cookie is single-use.
        self.cookies.remove(&data_key);

        let (prev_csrf_token, pkce_verifier, nonce, provider_name, oauth_flow) =
            serde_json::from_str::<(CsrfToken, String, Option<String>, String, OAuthFlow)>(
                &oauth_data,
            )?;

        if csrf_token.secret() != prev_csrf_token.secret() {
            return Err(OAuthCallbackError::CsrfMismatch);
        }

        // Context-carrying flows resolve the provider through the app's
        // resolver; everything else uses the statically configured providers.
        let provider = self
            .oauth_resolve_provider(oauth_flow.context(), &provider_name)
            .await?;

        let mut unmatched_token = provider
            .exchange_authorization_code(
                provider.name(),
                &self.redirect_uri(),
                &code,
                Some(PkceCodeVerifier::new(pkce_verifier)),
                nonce,
            )
            .await?;

        // Hand the context to the store alongside the token, so app-level
        // tenant logic can act on it at user/token creation.
        unmatched_token.context = oauth_flow.context().map(str::to_string);

        Ok((unmatched_token, oauth_flow, provider))
    }

    /// Resolve a provider: dynamically via the app's resolver when a context
    /// is given, otherwise from the static provider list.
    pub(crate) async fn oauth_resolve_provider(
        &self,
        context: Option<&str>,
        provider_name: &str,
    ) -> Result<Arc<dyn OAuthProvider>, OAuthCallbackError> {
        match context {
            Some(context) => self
                .oauth
                .provider_resolver
                .as_ref()
                .ok_or(OAuthCallbackError::NoProviderResolver)?
                .resolve(context, provider_name)
                .await?
                .ok_or_else(|| OAuthCallbackError::NoProvider(provider_name.to_string())),
            None => self
                .oauth
                .providers
                .get(provider_name)
                .cloned()
                .ok_or_else(|| OAuthCallbackError::NoProvider(provider_name.to_string())),
        }
    }

    /// Complete any OAuth flow: the flow type, provider and PKCE/nonce
    /// material all come from the encrypted state cookie selected by `state`.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_callback(
        mut self,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthGenericCallbackError<S::Error>> {
        let (unmatched_token, flow, provider) = match self.oauth_callback_inner(code, state).await {
            Ok(parts) => parts,
            Err(err) => {
                self.emit(crate::events::AuthEvent::OAuthCallbackFailed {
                    error: err.to_string(),
                });
                return Err(err.into());
            }
        };

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

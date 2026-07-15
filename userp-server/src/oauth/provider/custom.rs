use super::{ExchangeResult, OAuthProvider};
use crate::oauth::client::{
    ClientWithGenericExtraTokenFields, TokenResponseWithGenericExtraFields,
};
use crate::models::oauth::{OAuthProviderUser, UnmatchedOAuthToken};
use anyhow::Context;
use async_trait::async_trait;
use oauth2::{
    reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use std::{fmt::Display, future::Future, pin::Pin};
use url::Url;
use userp_client::models::Allow;

pub type OAuthProviderUserCallbackResult = anyhow::Result<OAuthProviderUser>;

trait AsyncOAuthProviderUserCallback: Send + Sync {
    fn call(
        &self,
        access_token: String,
        token_response: &TokenResponseWithGenericExtraFields,
    ) -> Pin<Box<dyn Future<Output = OAuthProviderUserCallbackResult> + Send>>;
}

impl<T, F> AsyncOAuthProviderUserCallback for T
where
    T: Fn(String, &TokenResponseWithGenericExtraFields) -> F + Sync + Send,
    F: Future<Output = OAuthProviderUserCallbackResult> + Send + 'static,
{
    fn call(
        &self,
        access_token: String,
        token_response: &TokenResponseWithGenericExtraFields,
    ) -> Pin<Box<dyn Future<Output = OAuthProviderUserCallbackResult> + Send>> {
        Box::pin(self(access_token, token_response))
    }
}

pub struct OAuthCustomProvider {
    client: ClientWithGenericExtraTokenFields,
    name: String,
    display_name: String,
    scopes: Vec<Scope>,
    get_user: Box<dyn AsyncOAuthProviderUserCallback>,
    allow_signup: Option<Allow>,
    allow_login: Option<Allow>,
    allow_linking: Option<bool>,
}

impl std::fmt::Debug for OAuthCustomProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCustomProvider")
            .field("client", &self.client)
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("scopes", &self.scopes)
            .field("get_user", &"You dont want no part of this Dewey")
            .field("allow_signup", &self.allow_signup)
            .field("allow_login", &self.allow_login)
            .field("allow_linking", &self.allow_linking)
            .finish()
    }
}

impl OAuthCustomProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_callback<Fut, F>(
        name: impl Into<String>,
        display_name: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        scopes: &[impl Display],
        get_user: F,
    ) -> Result<OAuthCustomProvider, anyhow::Error>
    where
        Fut: Future<Output = OAuthProviderUserCallbackResult> + Send + 'static,
        F: Fn(String, &TokenResponseWithGenericExtraFields) -> Fut + Send + Sync + 'static,
    {
        let client = ClientWithGenericExtraTokenFields::new(
            ClientId::new(client_id.into()),
            Some(ClientSecret::new(client_secret.into())),
            AuthUrl::from_url(Url::parse(&auth_url.into())?),
            Some(TokenUrl::from_url(Url::parse(&token_url.into())?)),
        );

        Ok(Self {
            allow_login: None,
            allow_signup: None,
            allow_linking: None,
            client,
            display_name: display_name.into(),
            scopes: scopes.iter().map(|s| Scope::new(s.to_string())).collect(),
            name: name.into(),
            get_user: Box::new(get_user),
        })
    }

    pub fn with_allow_signup(mut self, allow_signup: Option<Allow>) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn with_allow_login(mut self, allow_login: Option<Allow>) -> Self {
        self.allow_login = allow_login;
        self
    }

    pub fn with_allow_linking(mut self, allow_linking: Option<bool>) -> Self {
        self.allow_linking = allow_linking;
        self
    }
}

#[async_trait]
impl OAuthProvider for OAuthCustomProvider {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn display_name(&self) -> &str {
        self.display_name.as_str()
    }

    fn allow_signup(&self) -> Option<Allow> {
        self.allow_signup
    }

    fn allow_login(&self) -> Option<Allow> {
        self.allow_login
    }

    fn allow_linking(&self) -> Option<bool> {
        self.allow_linking
    }

    fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    fn get_authorization_url_and_state(
        &self,
        base_redirect_url: &RedirectUrl,
        scopes: &[Scope],
    ) -> (Url, CsrfToken, PkceCodeVerifier) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let client = self.client.clone().set_redirect_uri(base_redirect_url.clone());

        let (url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.to_vec())
            .set_pkce_challenge(pkce_challenge)
            .url();

        (url, csrf_state, pkce_verifier)
    }

    async fn exchange_authorization_code(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        code: &AuthorizationCode,
        pkce_verifier: Option<PkceCodeVerifier>,
    ) -> ExchangeResult {
        let client = self.client.clone().set_redirect_uri(redirect_url.clone());

        let mut req = client.exchange_code(code.clone());

        if let Some(pkce_verifier) = pkce_verifier {
            req = req.set_pkce_verifier(pkce_verifier);
        }

        let res = req
            .request_async(async_http_client)
            .await
            .context("Requesting authorization code exchange")?;

        let provider_user = self
            .get_user
            .call(res.access_token().secret().to_owned(), &res)
            .await?;

        Ok(UnmatchedOAuthToken::from_standard_token_response(
            &res,
            provider_name,
            provider_user,
        ))
    }

    async fn exchange_refresh_token(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        refresh_token: &RefreshToken,
    ) -> ExchangeResult {
        let res = self
            .client
            .clone()
            .set_redirect_uri(redirect_url.clone())
            .exchange_refresh_token(refresh_token)
            .request_async(async_http_client)
            .await
            .context("Requesting refresh token exchange")?;

        let provider_user = (self.get_user)
            .call(res.access_token().secret().to_owned(), &res)
            .await?;

        Ok(UnmatchedOAuthToken::from_standard_token_response(
            &res,
            provider_name,
            provider_user,
        ))
    }
}

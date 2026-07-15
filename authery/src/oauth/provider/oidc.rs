use super::{ExchangeResult, OAuthProvider};
use crate::{models::oauth::UnmatchedOAuthToken, oauth::client::ClientWithGenericExtraTokenFields};
use anyhow::Context;
use async_trait::async_trait;
use oauth2::{
    reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenUrl,
};
use std::fmt::Display;
use url::Url;
use crate::models::Allow;

/// ⚠️ Warning: JWT token signature is not checked yet.
#[derive(Debug)]
pub struct OAuthOidcProvider {
    client: ClientWithGenericExtraTokenFields,
    name: String,
    display_name: String,
    scopes: Vec<Scope>,
    allow_signup: Option<Allow>,
    allow_login: Option<Allow>,
    allow_linking: Option<bool>,
}

impl OAuthOidcProvider {
    /// ⚠️ Warning: JWT token signature is not checked yet.
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        scopes: &[impl Display],
    ) -> Result<OAuthOidcProvider, anyhow::Error> {
        let client = ClientWithGenericExtraTokenFields::new(
            ClientId::new(client_id.into()),
            Some(ClientSecret::new(client_secret.into())),
            AuthUrl::from_url(Url::parse(&auth_url.into())?),
            Some(TokenUrl::from_url(Url::parse(&token_url.into())?)),
        );

        let name = name.into();

        let mut has_openid_scope = false;
        let mut scopes = scopes
            .iter()
            .map(|s| {
                let s = s.to_string();

                if s == "openid" {
                    has_openid_scope = true
                };

                Scope::new(s.to_string())
            })
            .collect::<Vec<_>>();

        if !has_openid_scope {
            eprintln!("Missing 'openid' scope when building '{name}' Oidc provider. This is probably a mistake. Adding.");
            scopes.push(Scope::new("openid".into()));
        };

        Ok(Self {
            allow_login: None,
            allow_signup: None,
            allow_linking: None,
            client,
            display_name: display_name.into(),
            scopes,
            name,
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
impl OAuthProvider for OAuthOidcProvider {
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

        let provider_user = res
            .extra_fields()
            .get_oauth_oidc_provider_user_unvalidated()?;

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

        let provider_user = res
            .extra_fields()
            .get_oauth_oidc_provider_user_unvalidated()?;

        Ok(UnmatchedOAuthToken::from_standard_token_response(
            &res,
            provider_name,
            provider_user,
        ))
    }
}

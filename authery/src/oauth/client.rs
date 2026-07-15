use crate::models::oauth::OAuthProviderUser;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    Client, EndpointNotSet, EndpointSet, ExtraTokenFields, StandardRevocableToken,
    StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type TokenResponseWithGenericExtraFields =
    StandardTokenResponse<GenericExtraTokenFields, BasicTokenType>;

/// A freshly-constructed OAuth client, before any endpoint is set. `Client::new`
/// is defined on the five-parameter form (endpoints default to `EndpointNotSet`).
pub type ClientWithGenericExtraTokenFieldsBase = Client<
    BasicErrorResponse,
    TokenResponseWithGenericExtraFields,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

/// Our OAuth client, configured with the auth and token endpoints set (the two
/// endpoints authery uses) and the rest left unset, per oauth2 5's typestate.
pub type ClientWithGenericExtraTokenFields = Client<
    BasicErrorResponse,
    TokenResponseWithGenericExtraFields,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,    // auth url
    EndpointNotSet, // device auth url
    EndpointNotSet, // introspection url
    EndpointNotSet, // revocation url
    EndpointSet,    // token url
>;

/// A reqwest client that refuses to follow redirects, as recommended by oauth2
/// to prevent SSRF via the token endpoint.
pub(crate) fn http_client() -> Result<reqwest::Client> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Building the OAuth HTTP client")
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenericExtraTokenFields(pub Map<String, Value>);

impl ExtraTokenFields for GenericExtraTokenFields {}

impl GenericExtraTokenFields {
    pub(crate) fn get_oauth_oidc_provider_user_unvalidated(&self) -> Result<OAuthProviderUser> {
        let id_token = self.0["id_token"]
            .as_str()
            .context("Missing 'id_token' field in token response. Consider using non-oidc flow.")?
            .to_string();

        let body = id_token
            .split('.')
            .nth(1)
            .context("No body found. Misformed jwt?")?;
        let body = URL_SAFE_NO_PAD.decode(body)?;
        let body = serde_json::from_slice::<Value>(&body)?;

        let sub = body["sub"]
            .as_str()
            .context("Missing 'sub' in 'id_token'")?
            .to_string();

        Ok(OAuthProviderUser {
            id: sub,
            raw: self.0.clone().into(),
        })
    }
}

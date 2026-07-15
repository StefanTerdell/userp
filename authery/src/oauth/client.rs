use crate::models::oauth::OAuthProviderUser;
use anyhow::{bail, Context, Result};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
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

/// Discover the JWKS for an issuer and fetch its keys.
pub(crate) async fn fetch_jwks(issuer: &str) -> Result<JwkSet> {
    let client = http_client()?;

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let discovery = client
        .get(&discovery_url)
        .send()
        .await
        .context("Fetching OIDC discovery document")?
        .error_for_status()
        .context("OIDC discovery document request failed")?
        .json::<Value>()
        .await
        .context("Parsing OIDC discovery document")?;

    let jwks_uri = discovery["jwks_uri"]
        .as_str()
        .context("OIDC discovery document missing 'jwks_uri'")?;

    let jwks = client
        .get(jwks_uri)
        .send()
        .await
        .context("Fetching JWKS")?
        .error_for_status()
        .context("JWKS request failed")?
        .json::<JwkSet>()
        .await
        .context("Parsing JWKS")?;

    Ok(jwks)
}

/// Validate a raw OIDC id_token: verify its signature against `jwks` and check
/// the `iss`, `aud`, `exp` and (if provided) `nonce` claims. Returns the `sub`.
///
/// Exposed (not just used internally) so it can be exercised directly in tests
/// against a real identity provider.
pub fn validate_oidc_id_token(
    id_token: &str,
    jwks: &JwkSet,
    issuer: &str,
    audience: &str,
    expected_nonce: Option<&str>,
) -> Result<String> {
    let header = decode_header(id_token).context("Decoding id_token header")?;
    let kid = header
        .kid
        .context("id_token header missing 'kid'; cannot select a signing key")?;

    let jwk = jwks
        .find(&kid)
        .context("No JWK in the provider's key set matches the id_token 'kid'")?;
    let key = DecodingKey::from_jwk(jwk).context("Building decoding key from JWK")?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.validate_exp = true;

    let token = decode::<Value>(id_token, &key, &validation)
        .context("Validating id_token signature and claims")?;
    let claims = token.claims;

    // If we sent a nonce, the id_token must echo it back exactly.
    if let Some(expected) = expected_nonce {
        let got = claims["nonce"].as_str();
        if got != Some(expected) {
            bail!("id_token 'nonce' did not match the value sent in the request");
        }
    }

    claims["sub"]
        .as_str()
        .context("Missing 'sub' in validated 'id_token'")
        .map(|sub| sub.to_string())
}

impl GenericExtraTokenFields {
    /// Validate this response's id_token and extract the provider user.
    pub(crate) fn get_oauth_oidc_provider_user_validated(
        &self,
        jwks: &JwkSet,
        issuer: &str,
        audience: &str,
        expected_nonce: Option<&str>,
    ) -> Result<OAuthProviderUser> {
        let id_token = self.0["id_token"]
            .as_str()
            .context("Missing 'id_token' field in token response. Consider using non-oidc flow.")?;

        let sub = validate_oidc_id_token(id_token, jwks, issuer, audience, expected_nonce)?;

        Ok(OAuthProviderUser {
            id: sub,
            raw: self.0.clone().into(),
        })
    }
}

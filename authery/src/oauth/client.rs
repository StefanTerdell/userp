use crate::models::oauth::OAuthProviderUser;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    Client, ExtraTokenFields, StandardRevocableToken, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type TokenResponseWithGenericExtraFields =
    StandardTokenResponse<GenericExtraTokenFields, BasicTokenType>;

pub type ClientWithGenericExtraTokenFields = Client<
    BasicErrorResponse,
    TokenResponseWithGenericExtraFields,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

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

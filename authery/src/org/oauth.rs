//! Org-attached OIDC providers (SaaS mode): owners register their own SSO,
//! and members log in to the org through it at `/login/{slug}`.
//!
//! Providers live in the store as configuration and are built into live
//! [`OAuthOidcProvider`]s per request. The oauth state cookie carries the org
//! context ([`OAuthFlow::OrgLogIn`]) so the callback can resolve the same
//! provider again. On login, the validated id_token claims are mapped to org
//! roles ([`NewOrgOidcProvider::claim_role_mapping`]) and the membership is
//! upserted - the identity provider is authoritative for org access.

use crate::models::org::{NewOrgOidcProvider, OrgOidcProvider, Organization};
use crate::models::{oauth::UnmatchedOAuthToken, AutheryCookies, LoginMethod, User};
use crate::oauth::provider::{oidc::OAuthOidcProvider, OAuthProvider};
use crate::oauth::{login::OAuthLoginCallbackError, OAuthCallbackError, OAuthFlow};
use crate::org::OrgError;
use crate::{core::CoreAuthery, models::oauth::OAuthToken, store::AutheryStore};
use serde_json::Value;
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum OrgOAuthLoginInitError<StoreError: std::error::Error> {
    #[error("Organization not found")]
    OrgNotFound,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
    #[error("Login with this provider is not allowed")]
    NotAllowed,
    #[error("Provider misconfigured: {0}")]
    BadProviderConfig(#[from] anyhow::Error),
    #[error(transparent)]
    Store(StoreError),
}

/// Build a live provider from stored configuration.
fn build_provider<P: OrgOidcProvider>(config: &P) -> anyhow::Result<Arc<dyn OAuthProvider>> {
    Ok(Arc::new(OAuthOidcProvider::new(
        config.get_name(),
        config.get_display_name(),
        config.get_client_id(),
        config.get_client_secret(),
        config.get_issuer(),
        config.get_auth_url(),
        config.get_token_url(),
        &config.get_scopes(),
    )?))
}

/// Whether a mapping row matches the validated claims. Claim paths may be
/// dotted to reach into nested objects, e.g. Keycloak's `realm_access.roles`.
fn claim_matches(claims: &Value, claim: &str, value: &str) -> bool {
    let claim_value = claim
        .split('.')
        .fold(claims, |current, segment| &current[segment]);

    match claim_value {
        Value::String(s) => s == value,
        // Scalars match their canonical string rendering, so
        // ("email_verified", "true", ...) works on a boolean claim.
        Value::Bool(b) => b.to_string() == value,
        Value::Number(n) => n.to_string() == value,
        Value::Array(items) => items.iter().any(|i| i.as_str() == Some(value)),
        _ => false,
    }
}

/// App roles for a member logging in through this provider: the provider's
/// default roles plus every matched claim-role mapping row.
fn map_claim_roles<P: OrgOidcProvider>(config: &P, claims: &Value) -> Vec<String> {
    let mut roles = config.get_default_roles();

    for (claim, value, role) in config.get_claim_role_mapping() {
        if claim_matches(claims, &claim, &value) && !roles.contains(&role) {
            roles.push(role);
        }
    }

    roles
}

/// The highest privilege granted by the matched claim-privilege mapping rows.
fn map_claim_privilege<P: OrgOidcProvider>(
    config: &P,
    claims: &Value,
) -> Option<crate::models::org::OrgPrivilege> {
    config
        .get_claim_privilege_mapping()
        .into_iter()
        .filter(|(claim, value, _)| claim_matches(claims, claim, value))
        .map(|(_, _, privilege)| privilege)
        .max()
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Register or replace an org-attached OIDC provider. Requires the owner
    /// role.
    pub async fn org_oidc_upsert(
        &self,
        org_id: &S::OrgId,
        provider: NewOrgOidcProvider,
    ) -> Result<S::OrgOidcProvider, OrgError<S::Error>> {
        self.org_require(org_id, crate::models::org::OrgPrivilege::Owner).await?;

        Ok(self.store.org_oidc_upsert(org_id, provider).await?)
    }

    /// Delete an org-attached OIDC provider. Requires the owner role.
    pub async fn org_oidc_delete(
        &self,
        org_id: &S::OrgId,
        name: &str,
    ) -> Result<(), OrgError<S::Error>> {
        self.org_require(org_id, crate::models::org::OrgPrivilege::Owner).await?;

        Ok(self.store.org_oidc_delete(org_id, name).await?)
    }

    /// Begin an org-scoped OIDC login through one of the org's providers.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn org_oauth_login_init(
        self,
        org_slug: &str,
        provider_name: &str,
        next: Option<String>,
    ) -> Result<(Self, Url), OrgOAuthLoginInitError<S::Error>> {
        let Some(org) = self
            .store
            .org_get_by_slug(org_slug)
            .await
            .map_err(OrgOAuthLoginInitError::Store)?
        else {
            return Err(OrgOAuthLoginInitError::OrgNotFound);
        };

        let Some(config) = self
            .store
            .org_oidc_get(&org.get_id(), provider_name)
            .await
            .map_err(OrgOAuthLoginInitError::Store)?
        else {
            return Err(OrgOAuthLoginInitError::ProviderNotFound(
                provider_name.to_string(),
            ));
        };

        if !config.get_allow_login() {
            return Err(OrgOAuthLoginInitError::NotAllowed);
        }

        let provider = build_provider(&config)?;
        let path = self.routes.oauth.callbacks.login_oauth_provider.clone();

        Ok(self
            .oauth_init(
                path,
                provider,
                OAuthFlow::OrgLogIn {
                    org_id: org.get_id().to_string(),
                    next,
                },
            )
            .await)
    }

    /// Resolve an org provider for the oauth callback. Called with the
    /// org id string carried by [`OAuthFlow::OrgLogIn`].
    pub(crate) async fn org_oauth_provider(
        &self,
        org_id: &str,
        provider_name: &str,
    ) -> Result<Arc<dyn OAuthProvider>, OAuthCallbackError> {
        let config = self
            .org_oauth_provider_config(org_id, provider_name)
            .await?;

        build_provider(&config).map_err(OAuthCallbackError::ExchangeAuthorizationCodeError)
    }

    async fn org_oauth_provider_config(
        &self,
        org_id: &str,
        provider_name: &str,
    ) -> Result<S::OrgOidcProvider, OAuthCallbackError> {
        let Ok(org_id) = org_id.parse::<S::OrgId>() else {
            return Err(OAuthCallbackError::NoProvider(provider_name.to_string()));
        };

        self.store
            .org_oidc_get(&org_id, provider_name)
            .await
            .map_err(|err| OAuthCallbackError::OrgProviderLookup(err.to_string()))?
            .ok_or_else(|| OAuthCallbackError::NoProvider(provider_name.to_string()))
    }

    /// Complete an org-scoped OIDC login: resolve or create the user by the
    /// provider token, map the validated claims to org roles, upsert the
    /// membership, and log in.
    pub(crate) async fn org_oauth_login_callback_inner(
        self,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError<S::Error>> {
        let OAuthFlow::OrgLogIn { org_id, next } = flow else {
            return Err(OAuthLoginCallbackError::UnexpectedFlow(flow));
        };

        let config = self
            .org_oauth_provider_config(&org_id, &unmatched_token.provider_name)
            .await?;
        let Ok(org_id) = org_id.parse::<S::OrgId>() else {
            // org_oauth_provider_config already parsed this string.
            unreachable!("org id parsed by org_oauth_provider_config");
        };

        // The org's identity provider is authoritative: anyone it
        // authenticates becomes (or stays) a member.
        let (user, token) = match self
            .store
            .get_user_by_unmatched_token(unmatched_token.clone())
            .await
            .map_err(OAuthLoginCallbackError::Store)?
        {
            Some(user_token) => user_token,
            None => self
                .store
                .create_user_from_unmatched_token(unmatched_token.clone())
                .await
                .map_err(OAuthLoginCallbackError::Store)?,
        };

        let roles = map_claim_roles(&config, &unmatched_token.provider_user_raw);

        // Roles are IdP-authoritative and replaced on every login. The
        // privilege only ever upgrades: a mapped privilege is granted, but an
        // absent mapping must not strip an owner who happens to log in
        // through their own SSO.
        let existing_privilege = self
            .store
            .org_get_member(&org_id, &user.get_id())
            .await
            .map_err(OAuthLoginCallbackError::Store)?
            .and_then(|m| {
                use crate::models::org::OrgMember;
                m.get_privilege()
            });
        let privilege = existing_privilege
            .max(map_claim_privilege(&config, &unmatched_token.provider_user_raw));

        self.store
            .org_upsert_member(&org_id, &user.get_id(), privilege, roles)
            .await
            .map_err(OAuthLoginCallbackError::Store)?;

        Ok((
            self.log_in(
                LoginMethod::OAuth {
                    token_id: token.get_id().to_string(),
                },
                &user.get_id(),
            )
            .await
            .map_err(OAuthLoginCallbackError::Store)?,
            next,
        ))
    }
}

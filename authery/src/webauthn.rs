//! Passkey/authenticator support via `webauthn-rs`.
//!
//! Two ceremonies are wired up:
//!
//! - **Registration**: a logged-in user adds a passkey from the account page.
//!   `webauthn_register_start` returns the browser challenge and stashes the
//!   server-side ceremony state in the encrypted cookie jar;
//!   `webauthn_register_finish` validates the authenticator's response and
//!   persists the credential.
//! - **Login**: `webauthn_login_start`/`webauthn_login_finish` run a
//!   *discoverable* (usernameless) authentication - the browser picks the
//!   credential, we resolve the user by credential id. Non-resident security
//!   keys registered elsewhere may not support this; passkey providers do.
//!
//! Signing up with a passkey directly is intentionally not offered: a fresh
//! account needs some identifier to recover with anyway, so sign up with
//! email/password/oauth first and add a passkey after.

use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, LoginMethod},
    store::AutheryStore,
};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, WebauthnError,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

const WEBAUTHN_REG_KEY: &str = "authery-webauthn-reg";
const WEBAUTHN_AUTH_KEY: &str = "authery-webauthn-auth";

#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    pub webauthn: Webauthn,
}

impl WebauthnConfig {
    /// `rp_origin` is the URL the pages are served from (scheme + host +
    /// port); `rp_id` defaults to its effective domain. `rp_name` is what
    /// authenticators display to the user.
    pub fn new(rp_origin: Url, rp_name: &str) -> Result<Self, WebauthnError> {
        let rp_id = rp_origin
            .domain()
            .or_else(|| rp_origin.host_str())
            .ok_or(WebauthnError::Configuration)?
            .to_string();

        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name(rp_name)
            .build()?;

        Ok(Self { webauthn })
    }
}

#[derive(Debug, Error)]
pub enum WebauthnRegisterError<StoreError: std::error::Error> {
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("No registration in progress")]
    NoCeremony,
    #[error("Webauthn: {0}")]
    Webauthn(#[from] WebauthnError),
    #[error("Corrupt ceremony state: {0}")]
    BadState(#[from] serde_json::Error),
    #[error(transparent)]
    Store(StoreError),
}

#[derive(Debug, Error)]
pub enum WebauthnLoginError<StoreError: std::error::Error> {
    #[error("No login ceremony in progress")]
    NoCeremony,
    #[error("Unknown credential")]
    UnknownCredential,
    #[error("Webauthn: {0}")]
    Webauthn(#[from] WebauthnError),
    #[error("Corrupt ceremony state: {0}")]
    BadState(#[from] serde_json::Error),
    #[error(transparent)]
    Store(StoreError),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Begin registering a passkey for the logged-in user. Returns the
    /// challenge to pass to `navigator.credentials.create()`; the ceremony
    /// state rides in the encrypted cookie jar until the finish call.
    pub async fn webauthn_register_start(
        &mut self,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, WebauthnRegisterError<S::Error>> {
        let Some(session) = self
            .session()
            .await
            .map_err(WebauthnRegisterError::Store)?
        else {
            return Err(WebauthnRegisterError::NotLoggedIn);
        };

        use crate::models::LoginSession;
        let user_id = session.get_user_id();

        let existing = self
            .store
            .webauthn_get_credentials(&user_id)
            .await
            .map_err(WebauthnRegisterError::Store)?;

        let exclude = (!existing.is_empty())
            .then(|| existing.iter().map(|p| p.cred_id().clone()).collect());

        // The webauthn user handle is a random uuid, deliberately NOT derived
        // from the store's user id: login resolves by credential id, so the
        // generic id type stays unconstrained and no user id leaks into
        // authenticator hardware.
        let (mut ccr, reg_state) = self.webauthn.webauthn.start_passkey_registration(
            Uuid::new_v4(),
            display_name,
            display_name,
            exclude,
        )?;

        // `start_passkey_registration` leaves resident keys optional, but our
        // login flow is discoverable-only - a non-resident credential could be
        // registered yet never used. Upgrade the request to require a resident
        // key; the finish call does not re-check this policy.
        if let Some(selection) = ccr.public_key.authenticator_selection.as_mut() {
            selection.require_resident_key = true;
            selection.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
        }

        self.cookies
            .add(WEBAUTHN_REG_KEY, &serde_json::to_string(&reg_state)?);

        Ok(ccr)
    }

    /// Complete the registration ceremony and persist the new passkey.
    pub async fn webauthn_register_finish(
        &mut self,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<(), WebauthnRegisterError<S::Error>> {
        let Some(session) = self
            .session()
            .await
            .map_err(WebauthnRegisterError::Store)?
        else {
            return Err(WebauthnRegisterError::NotLoggedIn);
        };

        let Some(state_json) = self.cookies.get(WEBAUTHN_REG_KEY) else {
            return Err(WebauthnRegisterError::NoCeremony);
        };
        // The ceremony state is single-use either way.
        self.cookies.remove(WEBAUTHN_REG_KEY);

        let reg_state: PasskeyRegistration = serde_json::from_str(&state_json)?;

        let passkey = self
            .webauthn
            .webauthn
            .finish_passkey_registration(credential, &reg_state)?;

        use crate::models::LoginSession;
        self.store
            .webauthn_create_credential(&session.get_user_id(), passkey)
            .await
            .map_err(WebauthnRegisterError::Store)?;

        Ok(())
    }

    /// Begin a usernameless (discoverable) passkey login. Returns the
    /// challenge for `navigator.credentials.get()`.
    pub fn webauthn_login_start(
        &mut self,
    ) -> Result<RequestChallengeResponse, WebauthnLoginError<S::Error>> {
        let (rcr, auth_state) = self.webauthn.webauthn.start_discoverable_authentication()?;

        self.cookies
            .add(WEBAUTHN_AUTH_KEY, &serde_json::to_string(&auth_state)?);

        Ok(rcr)
    }

    /// Complete the login ceremony: resolve the credential, verify the
    /// assertion, persist counter updates, and create the session.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn webauthn_login_finish(
        mut self,
        credential: &PublicKeyCredential,
    ) -> Result<Self, WebauthnLoginError<S::Error>> {
        let Some(state_json) = self.cookies.get(WEBAUTHN_AUTH_KEY) else {
            return Err(WebauthnLoginError::NoCeremony);
        };
        self.cookies.remove(WEBAUTHN_AUTH_KEY);

        let auth_state: DiscoverableAuthentication = serde_json::from_str(&state_json)?;

        // Identify which credential the authenticator answered with, then
        // fetch it (and its owner) from the store.
        let (_user_handle, cred_id) = self
            .webauthn
            .webauthn
            .identify_discoverable_authentication(credential)?;

        let Some((user_id, passkey)) = self
            .store
            .webauthn_get_credential_by_credential_id(cred_id)
            .await
            .map_err(WebauthnLoginError::Store)?
        else {
            return Err(WebauthnLoginError::UnknownCredential);
        };

        let discoverable: DiscoverableKey = (&passkey).into();
        let result = self.webauthn.webauthn.finish_discoverable_authentication(
            credential,
            auth_state,
            &[discoverable],
        )?;

        // Persist counter/backup-state updates so clone detection works.
        let mut updated = passkey;
        if updated.update_credential(&result).unwrap_or(false) {
            self.store
                .webauthn_update_credential(&user_id, updated)
                .await
                .map_err(WebauthnLoginError::Store)?;
        }

        let credential_id = cred_id.iter().map(|b| format!("{b:02x}")).collect();

        self.log_in(LoginMethod::Webauthn { credential_id }, &user_id)
            .await
            .map_err(WebauthnLoginError::Store)
    }
}

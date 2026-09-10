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
use chrono::Utc;
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, WebauthnError,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

/// Ceremony cookies are keyed by the challenge so concurrent ceremonies (two
/// login tabs, a registration next to a login) don't clobber each other. The
/// finish call recovers the key from the challenge echoed in
/// `clientDataJSON`; the signed ceremony validation still compares it against
/// the encrypted state, so the echo only *selects* a cookie, never proves
/// anything.
pub(crate) fn ceremony_key(prefix: &str, challenge_b64: &str) -> String {
    format!("{prefix}-{challenge_b64}")
}

/// The canonical base64url (no padding) rendering of a challenge, matching
/// what browsers echo in `clientDataJSON`.
pub(crate) fn challenge_b64(
    challenge: &webauthn_rs::prelude::Base64UrlSafeData,
) -> Result<String, serde_json::Error> {
    Ok(serde_json::to_value(challenge)?
        .as_str()
        .unwrap_or_default()
        .to_string())
}

/// Extract the challenge from a raw `clientDataJSON` blob. `None` when the
/// blob isn't valid JSON - the ceremony lookup then fails as "no ceremony".
pub(crate) fn client_data_challenge(client_data_json: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct ClientData {
        challenge: webauthn_rs::prelude::Base64UrlSafeData,
    }

    let data: ClientData = serde_json::from_slice(client_data_json).ok()?;
    challenge_b64(&data.challenge).ok()
}

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

/// Registration state parked in the ceremony cookie, with the label the
/// finished passkey gets.
#[derive(serde::Serialize, serde::Deserialize)]
struct RegistrationCeremony {
    state: PasskeyRegistration,
    name: Option<String>,
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Begin registering a passkey for the logged-in user. Returns the
    /// challenge to pass to `navigator.credentials.create()`; the ceremony
    /// state rides in the encrypted cookie jar until the finish call.
    pub async fn webauthn_register_start(
        &mut self,
        display_name: &str,
        name: Option<String>,
    ) -> Result<CreationChallengeResponse, WebauthnRegisterError<S::Error>> {
        let Some(session) = self.session().await.map_err(WebauthnRegisterError::Store)? else {
            return Err(WebauthnRegisterError::NotLoggedIn);
        };

        use crate::models::LoginSession;
        let user_id = session.get_user_id();

        let existing = self
            .store
            .get_passkeys(&user_id)
            .await
            .map_err(WebauthnRegisterError::Store)?;

        let exclude = (!existing.is_empty()).then(|| {
            existing
                .iter()
                .map(|p| p.passkey.cred_id().clone())
                .collect()
        });

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

        self.cookies.add(
            &ceremony_key(
                &self.cookie_names.webauthn_register_prefix,
                &challenge_b64(&ccr.public_key.challenge)?,
            ),
            &serde_json::to_string(&RegistrationCeremony {
                state: reg_state,
                name,
            })?,
        );

        Ok(ccr)
    }

    /// Complete the registration ceremony and persist the new passkey.
    pub async fn webauthn_register_finish(
        &mut self,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<(), WebauthnRegisterError<S::Error>> {
        let Some(session) = self.session().await.map_err(WebauthnRegisterError::Store)? else {
            return Err(WebauthnRegisterError::NotLoggedIn);
        };

        let Some(state_key) = client_data_challenge(credential.response.client_data_json.as_ref())
            .map(|challenge| ceremony_key(&self.cookie_names.webauthn_register_prefix, &challenge))
        else {
            return Err(WebauthnRegisterError::NoCeremony);
        };
        let Some(state_json) = self.cookies.get(&state_key) else {
            return Err(WebauthnRegisterError::NoCeremony);
        };
        // The ceremony state is single-use either way.
        self.cookies.remove(&state_key);

        let RegistrationCeremony { state, name } = serde_json::from_str(&state_json)?;

        let passkey = self
            .webauthn
            .webauthn
            .finish_passkey_registration(credential, &state)?;

        use crate::models::LoginSession;
        self.store
            .create_passkey(
                &session.get_user_id(),
                crate::models::PasskeyRecord::new(passkey, name),
            )
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

        self.cookies.add(
            &ceremony_key(
                &self.cookie_names.webauthn_login_prefix,
                &challenge_b64(&rcr.public_key.challenge)?,
            ),
            &serde_json::to_string(&auth_state)?,
        );

        Ok(rcr)
    }

    /// Complete the login ceremony: resolve the credential, verify the
    /// assertion, persist counter updates, and create the session.
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn webauthn_login_finish(
        mut self,
        credential: &PublicKeyCredential,
    ) -> Result<Self, WebauthnLoginError<S::Error>> {
        let Some(state_key) = client_data_challenge(credential.response.client_data_json.as_ref())
            .map(|challenge| ceremony_key(&self.cookie_names.webauthn_login_prefix, &challenge))
        else {
            return Err(WebauthnLoginError::NoCeremony);
        };
        let Some(state_json) = self.cookies.get(&state_key) else {
            return Err(WebauthnLoginError::NoCeremony);
        };
        self.cookies.remove(&state_key);

        let auth_state: DiscoverableAuthentication = serde_json::from_str(&state_json)?;

        // Identify which credential the authenticator answered with, then
        // fetch it (and its owner) from the store.
        let (_user_handle, cred_id) = self
            .webauthn
            .webauthn
            .identify_discoverable_authentication(credential)?;

        let Some((user_id, mut record)) = self
            .store
            .get_passkey_by_credential_id(cred_id)
            .await
            .map_err(WebauthnLoginError::Store)?
        else {
            return Err(WebauthnLoginError::UnknownCredential);
        };

        let discoverable: DiscoverableKey = (&record.passkey).into();
        let result = self.webauthn.webauthn.finish_discoverable_authentication(
            credential,
            auth_state,
            &[discoverable],
        )?;

        // Persist counter/backup-state updates (clone detection) and the
        // last-used stamp.
        record.passkey.update_credential(&result);
        record.last_used = Some(Utc::now());
        self.store
            .update_passkey(&user_id, record)
            .await
            .map_err(WebauthnLoginError::Store)?;

        let credential_id = cred_id.iter().map(|b| format!("{b:02x}")).collect();

        self.log_in(LoginMethod::Webauthn { credential_id }, &user_id)
            .await
            .map_err(WebauthnLoginError::Store)
    }
}

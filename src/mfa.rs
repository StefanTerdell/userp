//! Multi-factor authentication as a policy layer over the other login methods.
//!
//! [`MfaPolicy`] names the first factors that must be backed by a second one.
//! When such a login succeeds and the user *has* a second factor registered,
//! the created session gets [`LoginMethod::MfaPending`] - treated as logged-out
//! everywhere except the MFA completion flow. Completing a second factor
//! deletes the pending session and creates a real one with
//! [`LoginMethod::Mfa`], recording both factors.
//!
//! Users without a registered second factor log in normally ("if configured"
//! semantics): hard-requiring MFA would lock out every fresh signup, so apps
//! that want mandatory MFA should steer users to register a factor and can
//! check `matches!(session.get_method(), LoginMethod::Mfa { .. })` on their
//! own sensitive routes.
//!
//! Available second factors:
//! - a passkey ceremony scoped to the user's registered credentials
//!   (`webauthn` feature)
//! - a code from the user's authenticator app (`totp` feature)
//! - a one-time code mailed to the user's own verified address (`otp`
//!   feature) - never to an address supplied in the request, and not offered
//!   when the first factor already proved control of the mailbox
//! - a one-time code texted to the user's own verified phone number (`sms`
//!   feature), with the same rules as emailed codes

use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, LoginMethod, LoginSession},
    store::AutheryStore,
};
use thiserror::Error;

/// Which first factors require a second factor (when the user has one
/// registered). The default requires MFA for password logins only: emailed
/// links/codes and oauth already involve a second system, while a password is
/// a pure knowledge factor.
#[derive(Debug, Clone)]
pub struct MfaPolicy {
    #[cfg(feature = "password")]
    pub require_for_password: bool,
    pub require_for_email: bool,
    #[cfg(feature = "email")]
    pub require_for_otp: bool,
    #[cfg(feature = "sms")]
    pub require_for_sms: bool,
    #[cfg(feature = "oauth")]
    pub require_for_oauth: bool,
    /// How long a device the user chose to trust after completing MFA may
    /// skip the second factor. `None` (the default) disables the option;
    /// the resulting sessions record [`LoginMethod::TrustedDevice`] as the
    /// second factor.
    pub trusted_device_lifetime: Option<chrono::Duration>,
    /// Codes per generated recovery batch (default 10).
    pub recovery_code_count: usize,
}

impl Default for MfaPolicy {
    fn default() -> Self {
        Self {
            #[cfg(feature = "password")]
            require_for_password: true,
            require_for_email: false,
            #[cfg(feature = "email")]
            require_for_otp: false,
            #[cfg(feature = "sms")]
            require_for_sms: false,
            #[cfg(feature = "oauth")]
            require_for_oauth: false,
            trusted_device_lifetime: None,
            recovery_code_count: 10,
        }
    }
}

impl MfaPolicy {
    fn requires_second_factor(&self, method: &LoginMethod) -> bool {
        match method {
            #[cfg(feature = "password")]
            LoginMethod::Password => self.require_for_password,
            #[cfg(feature = "email")]
            LoginMethod::Email { .. } => self.require_for_email,
            #[cfg(feature = "email")]
            LoginMethod::Otp { .. } => self.require_for_otp,
            #[cfg(feature = "sms")]
            LoginMethod::Sms { .. } => self.require_for_sms,
            #[cfg(feature = "oauth")]
            LoginMethod::OAuth { .. } => self.require_for_oauth,
            // Webauthn is already possession + user verification; purpose-bound
            // and second-factor methods never re-trigger.
            _ => false,
        }
    }
}

/// The second factors a pending user can choose from.
#[derive(Debug, Clone, Default)]
pub struct MfaFactors {
    /// The user has at least one passkey registered.
    pub webauthn: bool,
    /// The user has a confirmed authenticator-app enrollment.
    pub totp: bool,
    /// A code can be mailed to this (verified) address.
    pub otp_address: Option<String>,
    /// A code can be texted to this (verified) number.
    pub sms_number: Option<String>,
    /// The user has unused single-use recovery codes.
    pub recovery_codes: bool,
}

impl MfaFactors {
    pub fn any(&self) -> bool {
        self.webauthn
            || self.totp
            || self.otp_address.is_some()
            || self.sms_number.is_some()
            || self.recovery_codes
    }
}

#[derive(Debug, Error)]
pub enum MfaError<StoreError: std::error::Error> {
    #[error("No MFA login in progress")]
    NoPending,
    #[error("This second factor is not available")]
    FactorUnavailable,
    #[error(transparent)]
    Store(StoreError),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Called on every login: downgrade to a pending session when the policy
    /// demands a second factor the user actually has.
    pub(crate) async fn mfa_wrap_method(
        &self,
        method: LoginMethod,
        user_id: &S::UserId,
    ) -> Result<LoginMethod, S::Error> {
        if !self.mfa_policy.requires_second_factor(&method) {
            return Ok(method);
        }

        if !self.mfa_factors(user_id, &method).await?.any() {
            return Ok(method);
        }

        if self.device_trusted_for(user_id) {
            return Ok(LoginMethod::Mfa {
                first: Box::new(method),
                second: Box::new(LoginMethod::TrustedDevice),
            });
        }

        Ok(LoginMethod::MfaPending {
            first: Box::new(method),
        })
    }

    /// Whether the trusted-device cookie names this user and is still valid.
    fn device_trusted_for(&self, user_id: &S::UserId) -> bool {
        if self.mfa_policy.trusted_device_lifetime.is_none() {
            return false;
        }
        let Some(value) = self.cookies.get(&self.cookie_names.trusted_device) else {
            return false;
        };
        let Some((expires, cookie_user)) = value.split_once(':') else {
            return false;
        };
        let Ok(expires) = expires.parse::<i64>() else {
            return false;
        };
        expires > chrono::Utc::now().timestamp() && cookie_user == user_id.to_string()
    }

    /// Remember this device for the logged-in user so the next logins within
    /// [`MfaPolicy::trusted_device_lifetime`] skip the second factor. Returns
    /// `false` when the option is disabled or nobody is logged in.
    pub async fn trust_this_device(&mut self) -> Result<bool, S::Error> {
        let Some(lifetime) = self.mfa_policy.trusted_device_lifetime else {
            return Ok(false);
        };
        let Some(session) = self.session().await? else {
            return Ok(false);
        };

        let expires = (chrono::Utc::now() + lifetime).timestamp();
        self.cookies.add_persistent(
            &self.cookie_names.trusted_device,
            &format!("{expires}:{}", session.get_user_id()),
            lifetime,
        );

        Ok(true)
    }

    /// Forget this device; the next login runs the second factor again.
    pub fn forget_this_device(&mut self) {
        self.cookies.remove(&self.cookie_names.trusted_device);
    }

    /// The second factors available to this user, given the first factor
    /// already used. An emailed code is not offered when the first factor
    /// already proved control of the mailbox.
    pub async fn mfa_factors(
        &self,
        user_id: &S::UserId,
        first: &LoginMethod,
    ) -> Result<MfaFactors, S::Error> {
        let mut factors = MfaFactors::default();

        #[cfg(feature = "webauthn")]
        {
            factors.webauthn = !self.store.get_passkeys(user_id).await?.is_empty();
        }

        #[cfg(feature = "totp")]
        {
            factors.totp = self.totp_enabled(user_id).await?;
        }

        #[cfg(feature = "email")]
        {
            use crate::models::email::UserEmail;

            #[cfg(feature = "email")]
            let email_based_first =
                matches!(first, LoginMethod::Email { .. } | LoginMethod::Otp { .. });
            #[cfg(not(feature = "email"))]
            let email_based_first = matches!(first, LoginMethod::Otp { .. });

            if !email_based_first {
                factors.otp_address = self
                    .store
                    .get_user_emails(user_id)
                    .await?
                    .iter()
                    .find(|e| e.get_verified())
                    .map(|e| e.get_address().to_owned());
            }
        }

        #[cfg(feature = "sms")]
        {
            use crate::models::sms::UserPhone;

            // A texted code proves nothing extra when the first factor
            // already proved possession of the number.
            let sms_first = matches!(first, LoginMethod::Sms { .. });

            if !sms_first {
                factors.sms_number = self
                    .store
                    .get_user_phones(user_id)
                    .await?
                    .iter()
                    .find(|p| p.get_verified())
                    .map(|p| p.get_number().to_owned());
            }
        }

        #[cfg(not(any(feature = "email", feature = "sms")))]
        let _ = first;

        factors.recovery_codes = self.store.count_recovery_codes(user_id).await? > 0;

        Ok(factors)
    }

    /// The session awaiting a second factor, if any.
    pub async fn mfa_pending_session(&self) -> Result<Option<S::LoginSession>, S::Error> {
        let Some(session_id) = self.session_id_cookie() else {
            return Ok(None);
        };

        let Some(session) = self.store.get_session(&session_id).await? else {
            return Ok(None);
        };

        if session.is_expired() {
            self.store
                .delete_session(&session.get_user_id(), &session.get_id())
                .await?;
            return Ok(None);
        }

        Ok(Some(session).filter(|s| matches!(s.get_method(), LoginMethod::MfaPending { .. })))
    }

    /// Replace the pending session with a full one recording both factors.
    /// Callers must have verified `second` against this user.
    pub(crate) async fn mfa_upgrade(
        mut self,
        pending: S::LoginSession,
        second: LoginMethod,
    ) -> Result<Self, S::Error> {
        let LoginMethod::MfaPending { first } = pending.get_method() else {
            // Guarded by every caller; a non-pending session never gets here.
            return Ok(self);
        };

        let user_id = pending.get_user_id();

        self.store
            .delete_session(&user_id, &pending.get_id())
            .await?;
        self.cookies.remove(&self.cookie_names.session_id);

        self.log_in(
            LoginMethod::Mfa {
                first,
                second: Box::new(second),
            },
            &user_id,
        )
        .await
    }
}

#[cfg(feature = "email")]
mod otp_factor {
    use super::*;
    use crate::email::SendEmailChallengeError;
    use crate::models::email::EmailChallenge;
    use crate::ratelimit::{RateLimitOp, RateLimited};
    use chrono::Utc;

    fn challenge_key(address: &str, code: &str) -> String {
        format!("mfa:{address}:{code}")
    }

    #[derive(Debug, Error)]
    pub enum MfaOtpError<StoreError: std::error::Error> {
        #[error("No MFA login in progress")]
        NoPending,
        #[error("This second factor is not available")]
        FactorUnavailable,
        #[error("Wrong or expired code")]
        WrongCode,
        #[error(transparent)]
        RateLimited(RateLimited),
        #[error(transparent)]
        SendingEmail(SendEmailChallengeError<StoreError>),
        #[error(transparent)]
        Store(StoreError),
    }

    crate::ratelimit::impl_maybe_rate_limited!(MfaOtpError, RateLimited);

    impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
        /// Mail a second-factor code to the pending user's own verified
        /// address. The address is never taken from the request.
        pub async fn mfa_otp_init(&self) -> Result<String, MfaOtpError<S::Error>> {
            let (_pending, address) = self.mfa_otp_target().await?;

            self.check_rate(RateLimitOp::EmailSend { address: &address })
                .await
                .map_err(MfaOtpError::RateLimited)?;

            let digits = self.email.code_generator.generate();
            let key = challenge_key(&address, &digits);

            self.store
                .create_challenge(
                    address.clone(),
                    key,
                    None,
                    Utc::now() + self.email.challenge_lifetime,
                )
                .await
                .map_err(MfaOtpError::Store)?;

            let content = self.email.messages.mfa_code(&digits);
            self.send_email(&address, &content.subject, content.html_body)
                .await
                .map_err(MfaOtpError::SendingEmail)?;

            Ok(address)
        }

        /// Verify the mailed code and upgrade the pending session.
        #[must_use = "Don't forget to return the auth session as part of the response!"]
        pub async fn mfa_otp_verify(self, code: &str) -> Result<Self, MfaOtpError<S::Error>> {
            let (pending, address) = self.mfa_otp_target().await?;

            self.check_rate(RateLimitOp::OtpAttempt { address: &address })
                .await
                .map_err(MfaOtpError::RateLimited)?;

            let Some(challenge) = self
                .store
                .consume_challenge(challenge_key(&address, code))
                .await
                .map_err(MfaOtpError::Store)?
            else {
                self.emit(crate::events::AuthEvent::CodeRejected {
                    channel: crate::events::CodeChannel::MfaEmail,
                    identifier: address.clone(),
                });
                return Err(MfaOtpError::WrongCode);
            };

            if challenge.get_expires() < Utc::now() {
                self.emit(crate::events::AuthEvent::CodeRejected {
                    channel: crate::events::CodeChannel::MfaEmail,
                    identifier: address,
                });
                return Err(MfaOtpError::WrongCode);
            }

            self.mfa_upgrade(pending, LoginMethod::Otp { address })
                .await
                .map_err(MfaOtpError::Store)
        }

        /// The pending session and the verified address codes go to.
        async fn mfa_otp_target(&self) -> Result<(S::LoginSession, String), MfaOtpError<S::Error>> {
            let Some(pending) = self
                .mfa_pending_session()
                .await
                .map_err(MfaOtpError::Store)?
            else {
                return Err(MfaOtpError::NoPending);
            };

            let LoginMethod::MfaPending { first } = pending.get_method() else {
                return Err(MfaOtpError::NoPending);
            };

            let factors = self
                .mfa_factors(&pending.get_user_id(), &first)
                .await
                .map_err(MfaOtpError::Store)?;

            match factors.otp_address {
                Some(address) => Ok((pending, address)),
                None => Err(MfaOtpError::FactorUnavailable),
            }
        }
    }
}

#[cfg(feature = "email")]
pub use otp_factor::MfaOtpError;

#[cfg(feature = "webauthn")]
mod webauthn_factor {
    use super::*;
    use webauthn_rs::prelude::{
        PasskeyAuthentication, PublicKeyCredential, RequestChallengeResponse, WebauthnError,
    };

    #[derive(Debug, Error)]
    pub enum MfaWebauthnError<StoreError: std::error::Error> {
        #[error("No MFA login in progress")]
        NoPending,
        #[error("This second factor is not available")]
        FactorUnavailable,
        #[error("No ceremony in progress")]
        NoCeremony,
        #[error("Webauthn: {0}")]
        Webauthn(#[from] WebauthnError),
        #[error("Corrupt ceremony state: {0}")]
        BadState(#[from] serde_json::Error),
        #[error(transparent)]
        Store(StoreError),
    }

    impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
        /// Begin a passkey ceremony scoped to the pending user's credentials.
        pub async fn mfa_webauthn_start(
            &mut self,
        ) -> Result<RequestChallengeResponse, MfaWebauthnError<S::Error>> {
            let Some(pending) = self
                .mfa_pending_session()
                .await
                .map_err(MfaWebauthnError::Store)?
            else {
                return Err(MfaWebauthnError::NoPending);
            };

            let passkeys = self
                .store
                .get_passkeys(&pending.get_user_id())
                .await
                .map_err(MfaWebauthnError::Store)?;

            if passkeys.is_empty() {
                return Err(MfaWebauthnError::FactorUnavailable);
            }

            let passkeys: Vec<_> = passkeys.into_iter().map(|p| p.passkey).collect();
            let (rcr, auth_state) = self
                .webauthn
                .webauthn
                .start_passkey_authentication(&passkeys)?;

            self.cookies.add(
                &crate::webauthn::ceremony_key(
                    &self.cookie_names.mfa_webauthn_prefix,
                    &crate::webauthn::challenge_b64(&rcr.public_key.challenge)?,
                ),
                &serde_json::to_string(&auth_state)?,
            );

            Ok(rcr)
        }

        /// Verify the assertion and upgrade the pending session.
        #[must_use = "Don't forget to return the auth session as part of the response!"]
        pub async fn mfa_webauthn_finish(
            mut self,
            credential: &PublicKeyCredential,
        ) -> Result<Self, MfaWebauthnError<S::Error>> {
            let Some(pending) = self
                .mfa_pending_session()
                .await
                .map_err(MfaWebauthnError::Store)?
            else {
                return Err(MfaWebauthnError::NoPending);
            };

            let Some(state_key) = crate::webauthn::client_data_challenge(
                credential.response.client_data_json.as_ref(),
            )
            .map(|challenge| {
                crate::webauthn::ceremony_key(&self.cookie_names.mfa_webauthn_prefix, &challenge)
            }) else {
                return Err(MfaWebauthnError::NoCeremony);
            };
            let Some(state_json) = self.cookies.get(&state_key) else {
                return Err(MfaWebauthnError::NoCeremony);
            };
            self.cookies.remove(&state_key);

            let auth_state: PasskeyAuthentication = serde_json::from_str(&state_json)?;

            // The state carries the allowed credentials from start (this
            // user's passkeys), so a foreign credential fails verification.
            let result = self
                .webauthn
                .webauthn
                .finish_passkey_authentication(credential, &auth_state)?;

            let user_id = pending.get_user_id();

            // Persist counter/backup-state updates and the last-used stamp.
            let passkeys = self
                .store
                .get_passkeys(&user_id)
                .await
                .map_err(MfaWebauthnError::Store)?;
            if let Some(mut record) = passkeys
                .into_iter()
                .find(|p| p.passkey.cred_id() == result.cred_id())
            {
                record.passkey.update_credential(&result);
                record.last_used = Some(chrono::Utc::now());
                self.store
                    .update_passkey(&user_id, record)
                    .await
                    .map_err(MfaWebauthnError::Store)?;
            }

            let credential_id = result
                .cred_id()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();

            self.mfa_upgrade(pending, LoginMethod::Webauthn { credential_id })
                .await
                .map_err(MfaWebauthnError::Store)
        }
    }
}

#[cfg(feature = "webauthn")]
pub use webauthn_factor::MfaWebauthnError;

#[cfg(feature = "totp")]
mod totp_factor {
    use super::*;
    use crate::totp::TotpError;

    #[derive(Debug, Error)]
    pub enum MfaTotpError<StoreError: std::error::Error> {
        #[error("No MFA login in progress")]
        NoPending,
        #[error(transparent)]
        Totp(TotpError<StoreError>),
        #[error(transparent)]
        Store(StoreError),
    }

    impl<E: std::error::Error> crate::ratelimit::MaybeRateLimited for MfaTotpError<E> {
        fn rate_limited(&self) -> Option<&crate::ratelimit::RateLimited> {
            match self {
                Self::Totp(inner) => inner.rate_limited(),
                _ => None,
            }
        }
    }

    impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
        /// Verify an authenticator-app code and upgrade the pending session.
        #[must_use = "Don't forget to return the auth session as part of the response!"]
        pub async fn mfa_totp_verify(self, code: &str) -> Result<Self, MfaTotpError<S::Error>> {
            let Some(pending) = self
                .mfa_pending_session()
                .await
                .map_err(MfaTotpError::Store)?
            else {
                return Err(MfaTotpError::NoPending);
            };

            self.totp_verify(&pending.get_user_id(), code)
                .await
                .map_err(MfaTotpError::Totp)?;

            self.mfa_upgrade(pending, LoginMethod::Totp)
                .await
                .map_err(MfaTotpError::Store)
        }
    }
}

#[cfg(feature = "totp")]
pub use totp_factor::MfaTotpError;

#[cfg(feature = "sms")]
mod sms_factor {
    use super::*;
    use crate::models::email::EmailChallenge;
    use crate::ratelimit::{RateLimitOp, RateLimited};
    use crate::sms::SmsSendError;
    use chrono::Utc;

    fn challenge_key(number: &str, code: &str) -> String {
        format!("mfasms:{number}:{code}")
    }

    #[derive(Debug, Error)]
    pub enum MfaSmsError<StoreError: std::error::Error> {
        #[error("No MFA login in progress")]
        NoPending,
        #[error("This second factor is not available")]
        FactorUnavailable,
        #[error("Wrong or expired code")]
        WrongCode,
        #[error("Could not send the text message, please try again later")]
        Send(#[from] SmsSendError),
        #[error(transparent)]
        RateLimited(RateLimited),
        #[error(transparent)]
        Store(StoreError),
    }

    crate::ratelimit::impl_maybe_rate_limited!(MfaSmsError, RateLimited);

    impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
        /// Text a second-factor code to the pending user's own verified
        /// number. The number is never taken from the request.
        pub async fn mfa_sms_init(&self) -> Result<String, MfaSmsError<S::Error>> {
            let (_pending, number) = self.mfa_sms_target().await?;

            self.check_rate(RateLimitOp::SmsSend { number: &number })
                .await
                .map_err(MfaSmsError::RateLimited)?;

            let digits = self.sms.code_generator.generate();
            let key = challenge_key(&number, &digits);

            self.store
                .create_challenge(
                    number.clone(),
                    key,
                    None,
                    Utc::now() + self.sms.challenge_lifetime,
                )
                .await
                .map_err(MfaSmsError::Store)?;

            self.send_sms(&number, &self.sms.messages.mfa_code(&digits))
                .await?;

            Ok(number)
        }

        /// Verify the texted code and upgrade the pending session.
        #[must_use = "Don't forget to return the auth session as part of the response!"]
        pub async fn mfa_sms_verify(self, code: &str) -> Result<Self, MfaSmsError<S::Error>> {
            let (pending, number) = self.mfa_sms_target().await?;

            self.check_rate(RateLimitOp::SmsAttempt { number: &number })
                .await
                .map_err(MfaSmsError::RateLimited)?;

            let Some(challenge) = self
                .store
                .consume_challenge(challenge_key(&number, code))
                .await
                .map_err(MfaSmsError::Store)?
            else {
                self.emit(crate::events::AuthEvent::CodeRejected {
                    channel: crate::events::CodeChannel::MfaSms,
                    identifier: number.clone(),
                });
                return Err(MfaSmsError::WrongCode);
            };

            if challenge.get_expires() < Utc::now() {
                self.emit(crate::events::AuthEvent::CodeRejected {
                    channel: crate::events::CodeChannel::MfaSms,
                    identifier: number,
                });
                return Err(MfaSmsError::WrongCode);
            }

            self.mfa_upgrade(pending, LoginMethod::Sms { number })
                .await
                .map_err(MfaSmsError::Store)
        }

        /// The pending session and the verified number codes go to.
        async fn mfa_sms_target(&self) -> Result<(S::LoginSession, String), MfaSmsError<S::Error>> {
            let Some(pending) = self
                .mfa_pending_session()
                .await
                .map_err(MfaSmsError::Store)?
            else {
                return Err(MfaSmsError::NoPending);
            };

            let LoginMethod::MfaPending { first } = pending.get_method() else {
                return Err(MfaSmsError::NoPending);
            };

            let factors = self
                .mfa_factors(&pending.get_user_id(), &first)
                .await
                .map_err(MfaSmsError::Store)?;

            match factors.sms_number {
                Some(number) => Ok((pending, number)),
                None => Err(MfaSmsError::FactorUnavailable),
            }
        }
    }
}

#[cfg(feature = "sms")]
pub use sms_factor::MfaSmsError;

pub use recovery::{MfaRecoveryError, RecoveryCodesError, hash_recovery_code};

mod recovery {
    use super::*;
    use crate::ratelimit::{RateLimitOp, RateLimited};
    use sha2::{Digest, Sha256};

    /// The canonical hash of a recovery code: SHA-256 hex over the
    /// normalized form (lowercased, separators stripped). Codes carry ~50
    /// bits of CSPRNG entropy, so a fast hash suffices against offline
    /// attack on a leaked store - unlike passwords, which are chosen.
    pub fn hash_recovery_code(code: &str) -> String {
        let normalized: String = code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();

        format!("{:x}", Sha256::digest(normalized.as_bytes()))
    }

    /// Ten random base32 characters as `xxxxx-xxxxx`, from the CSPRNG behind
    /// UUIDv4. The alphabet avoids `0/1/8/9` lookalike ambiguity.
    fn generate_code() -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut bits = uuid::Uuid::new_v4().as_u128();
        let mut chars = Vec::with_capacity(11);

        for i in 0..10 {
            if i == 5 {
                chars.push(b'-');
            }
            chars.push(ALPHABET[(bits & 31) as usize]);
            bits >>= 5;
        }

        String::from_utf8(chars).expect("ascii")
    }

    #[derive(Debug, Error)]
    pub enum RecoveryCodesError<StoreError: std::error::Error> {
        #[error("Not logged in")]
        NotLoggedIn,
        #[error(transparent)]
        Store(StoreError),
    }

    #[derive(Debug, Error)]
    pub enum MfaRecoveryError<StoreError: std::error::Error> {
        #[error("No MFA login in progress")]
        NoPending,
        #[error("Wrong or already-used code")]
        WrongCode,
        #[error(transparent)]
        RateLimited(RateLimited),
        #[error(transparent)]
        Store(StoreError),
    }

    crate::ratelimit::impl_maybe_rate_limited!(MfaRecoveryError, RateLimited);

    impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
        /// Generate a fresh batch of recovery codes for the logged-in user,
        /// replacing any previous batch. The plaintext codes are returned
        /// exactly once - only their hashes are stored.
        pub async fn recovery_codes_generate(
            &self,
        ) -> Result<Vec<String>, RecoveryCodesError<S::Error>> {
            let Some(session) = self.session().await.map_err(RecoveryCodesError::Store)? else {
                return Err(RecoveryCodesError::NotLoggedIn);
            };

            let codes: Vec<String> = (0..self.mfa_policy.recovery_code_count)
                .map(|_| generate_code())
                .collect();
            let hashes = codes.iter().map(|c| hash_recovery_code(c)).collect();

            self.store
                .set_recovery_code_hashes(&session.get_user_id(), hashes)
                .await
                .map_err(RecoveryCodesError::Store)?;

            Ok(codes)
        }

        /// How many unused recovery codes the logged-in user has left.
        pub async fn recovery_codes_count(&self) -> Result<usize, RecoveryCodesError<S::Error>> {
            let Some(session) = self.session().await.map_err(RecoveryCodesError::Store)? else {
                return Err(RecoveryCodesError::NotLoggedIn);
            };

            self.store
                .count_recovery_codes(&session.get_user_id())
                .await
                .map_err(RecoveryCodesError::Store)
        }

        /// Consume a recovery code as the second factor and upgrade the
        /// pending session. Each code works exactly once.
        #[must_use = "Don't forget to return the auth session as part of the response!"]
        pub async fn mfa_recovery_verify(
            self,
            code: &str,
        ) -> Result<Self, MfaRecoveryError<S::Error>> {
            let Some(pending) = self
                .mfa_pending_session()
                .await
                .map_err(MfaRecoveryError::Store)?
            else {
                return Err(MfaRecoveryError::NoPending);
            };

            let user_id = pending.get_user_id();

            self.check_rate(RateLimitOp::RecoveryAttempt {
                user_id: &user_id.to_string(),
            })
            .await
            .map_err(MfaRecoveryError::RateLimited)?;

            let consumed = self
                .store
                .consume_recovery_code_hash(&user_id, &hash_recovery_code(code))
                .await
                .map_err(MfaRecoveryError::Store)?;

            if !consumed {
                self.emit(crate::events::AuthEvent::CodeRejected {
                    channel: crate::events::CodeChannel::RecoveryCode,
                    identifier: user_id.to_string(),
                });
                return Err(MfaRecoveryError::WrongCode);
            }

            self.mfa_upgrade(pending, LoginMethod::RecoveryCode)
                .await
                .map_err(MfaRecoveryError::Store)
        }
    }
}

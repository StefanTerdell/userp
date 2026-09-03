//! TOTP (authenticator-app codes, RFC 6238) as an MFA second factor.
//!
//! Enrollment is a two-step ceremony on the account page: `totp_enroll_start`
//! generates a secret (shown as a QR code and otpauth URL), and
//! `totp_enroll_confirm` activates it only once the user proves they can
//! produce a valid code - an unconfirmed enrollment is never accepted as a
//! factor, so a closed tab can't lock anyone out.
//!
//! Verification accepts one time-step of clock skew in each direction and
//! rejects replays: the last accepted step is persisted, and codes at or
//! before it fail (RFC 6238 §5.2). Attempts pass through the
//! [`RateLimitOp::TotpAttempt`] hook - six digits are guessable, keep it
//! tight.
//!
//! TOTP is deliberately not a standalone login method; it proves "same
//! phone", not "who". With the `mfa` feature it becomes a second factor next
//! to passkeys and emailed codes.

use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, TotpCredential, User},
    ratelimit::{RateLimitOp, RateLimited},
    store::AutheryStore,
};
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};

/// Configuration for TOTP enrollment. The issuer is what authenticator apps
/// display next to the account label.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub issuer: String,
}

impl TotpConfig {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
        }
    }
}

/// Everything the enrollment page needs to show.
#[derive(Debug, Clone)]
pub struct TotpEnrollment {
    /// The base32 secret, for manual entry.
    pub secret: String,
    /// The `otpauth://` URL encoding secret + issuer + account.
    pub otpauth_url: String,
    /// A QR code of the otpauth URL as a base64 PNG, ready for
    /// `<img src="data:image/png;base64,{qr}">`.
    pub qr_png_base64: String,
}

#[derive(Debug, Error)]
pub enum TotpError<StoreError: std::error::Error> {
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("No TOTP enrollment in progress")]
    NotEnrolled,
    #[error("Wrong code")]
    WrongCode,
    #[error("TOTP misconfigured: {0}")]
    Totp(String),
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    Store(StoreError),
}

crate::ratelimit::impl_maybe_rate_limited!(TotpError, RateLimited);

/// Build the RFC 6238 verifier: SHA-1, 6 digits, 30s steps, ±1 step skew -
/// what every authenticator app expects.
fn build_totp<E: std::error::Error>(
    secret: &str,
    issuer: &str,
    account: &str,
) -> Result<TOTP, TotpError<E>> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|err| TotpError::Totp(err.to_string()))?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|err| TotpError::Totp(err.to_string()))
}

fn current_step(totp: &TOTP) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
        / totp.step
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Begin TOTP enrollment for the logged-in user: generate and store an
    /// unconfirmed secret (replacing any previous unconfirmed one) and return
    /// what the page needs to display. `account_label` is what the
    /// authenticator shows below the issuer - typically the user's email.
    pub async fn totp_enroll_start(
        &self,
        account_label: &str,
    ) -> Result<TotpEnrollment, TotpError<S::Error>> {
        let Some((user, _session)) = self.user_session().await.map_err(TotpError::Store)? else {
            return Err(TotpError::NotLoggedIn);
        };

        let secret = Secret::generate_secret().to_encoded().to_string();
        let totp = build_totp::<S::Error>(&secret, &self.totp.issuer, account_label)?;

        self.store
            .upsert_totp(
                &user.get_id(),
                TotpCredential {
                    secret: secret.clone(),
                    confirmed: false,
                    last_used_step: None,
                },
            )
            .await
            .map_err(TotpError::Store)?;

        Ok(TotpEnrollment {
            otpauth_url: totp.get_url(),
            qr_png_base64: totp
                .get_qr_base64()
                .map_err(|err| TotpError::Totp(err.to_string()))?,
            secret,
        })
    }

    /// Activate the enrollment by proving a code from the authenticator.
    pub async fn totp_enroll_confirm(&self, code: &str) -> Result<(), TotpError<S::Error>> {
        let Some((user, _session)) = self.user_session().await.map_err(TotpError::Store)? else {
            return Err(TotpError::NotLoggedIn);
        };
        let user_id = user.get_id();

        let Some(credential) = self
            .store
            .get_totp(&user_id)
            .await
            .map_err(TotpError::Store)?
        else {
            return Err(TotpError::NotEnrolled);
        };

        let step = self.totp_check_code(&user_id, &credential, code).await?;

        self.store
            .upsert_totp(
                &user_id,
                TotpCredential {
                    confirmed: true,
                    last_used_step: Some(step),
                    ..credential
                },
            )
            .await
            .map_err(TotpError::Store)?;

        Ok(())
    }

    /// Remove the logged-in user's TOTP enrollment.
    pub async fn totp_disable(&self) -> Result<(), TotpError<S::Error>> {
        let Some((user, _session)) = self.user_session().await.map_err(TotpError::Store)? else {
            return Err(TotpError::NotLoggedIn);
        };

        self.store
            .delete_totp(&user.get_id())
            .await
            .map_err(TotpError::Store)
    }

    /// Whether the user has a CONFIRMED enrollment (i.e. TOTP is usable as a
    /// factor).
    pub async fn totp_enabled(&self, user_id: &S::UserId) -> Result<bool, S::Error> {
        Ok(self
            .store
            .get_totp(user_id)
            .await?
            .is_some_and(|c| c.confirmed))
    }

    /// Verify a code against a CONFIRMED enrollment and persist the replay
    /// guard. Used by the MFA completion flow.
    pub(crate) async fn totp_verify(
        &self,
        user_id: &S::UserId,
        code: &str,
    ) -> Result<(), TotpError<S::Error>> {
        let Some(credential) = self
            .store
            .get_totp(user_id)
            .await
            .map_err(TotpError::Store)?
        else {
            return Err(TotpError::NotEnrolled);
        };

        if !credential.confirmed {
            return Err(TotpError::NotEnrolled);
        }

        let step = self.totp_check_code(user_id, &credential, code).await?;

        self.store
            .upsert_totp(
                user_id,
                TotpCredential {
                    last_used_step: Some(step),
                    ..credential
                },
            )
            .await
            .map_err(TotpError::Store)?;

        Ok(())
    }

    /// Rate-limit, verify the code (±1 step skew), and enforce the replay
    /// guard. Returns the current step to persist.
    async fn totp_check_code(
        &self,
        user_id: &S::UserId,
        credential: &TotpCredential,
        code: &str,
    ) -> Result<u64, TotpError<S::Error>> {
        let user_id_str = user_id.to_string();
        self.check_rate(RateLimitOp::TotpAttempt {
            user_id: &user_id_str,
        })
        .await
        .map_err(TotpError::RateLimited)?;

        // The account label only affects the otpauth URL, not verification.
        let totp = build_totp::<S::Error>(&credential.secret, &self.totp.issuer, "verify")?;

        // Find WHICH step (within ±1 skew) the code matches, so the replay
        // guard compares against the matched step rather than the wall clock:
        // a next-step code arriving early must pass even though the previous
        // step's code was just consumed.
        let current = current_step(&totp);
        let matched_step = (-1i64..=1).find_map(|offset| {
            let step = current.checked_add_signed(offset)?;
            (totp.generate(step * totp.step) == code).then_some(step)
        });

        let Some(step) = matched_step else {
            self.emit(crate::events::AuthEvent::CodeRejected {
                channel: crate::events::CodeChannel::Totp,
                identifier: user_id_str,
            });
            return Err(TotpError::WrongCode);
        };

        // Replay guard (RFC 6238 §5.2): each step's code is single-use, and
        // steps only move forward.
        if credential.last_used_step.is_some_and(|last| step <= last) {
            self.emit(crate::events::AuthEvent::CodeRejected {
                channel: crate::events::CodeChannel::Totp,
                identifier: user_id_str,
            });
            return Err(TotpError::WrongCode);
        }

        Ok(step)
    }
}

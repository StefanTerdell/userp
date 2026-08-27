//! Observability for the events your store never sees.
//!
//! The store observes successful user creations, logins and token
//! exchanges, but an app that wants to alert on *failed* logins, code
//! guessing or rate-limit hits needs a hook on the failure paths. Register
//! an [`AuthEventHandler`] with
//! [`with_event_handler`](crate::config::AutheryConfig::with_event_handler);
//! the default handler logs every event through [`tracing`] at
//! `info`/`warn`, so wiring a `tracing` subscriber is all it takes to get
//! useful auth logs out of the box.
//!
//! Handlers are synchronous and called inline on the request path - keep
//! them cheap (log, count, channel-send) and spawn for anything slow.

use crate::models::LoginMethod;

/// Something auth-relevant happened. Variants carry owned strings so
/// handlers can ship them across threads freely; the enum is
/// `#[non_exhaustive]` - new variants are not breaking changes, so match
/// with a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum AuthEvent {
    /// A session was created - any method, including MFA-pending
    /// downgrades (inspect the method).
    LoginSucceeded {
        user_id: String,
        method: LoginMethod,
    },
    /// A password login or signup-against-existing-user failed. Fires for
    /// unknown users too; the identifier may not exist, so don't treat the
    /// event as confirmation.
    #[cfg(feature = "password")]
    PasswordRejected { password_id: String },
    /// A one-time code, authenticator code or recovery code was rejected.
    CodeRejected {
        channel: CodeChannel,
        /// The address/number/user id the attempt targeted.
        identifier: String,
    },
    /// An OAuth callback failed (state mismatch, exchange failure, ...).
    #[cfg(feature = "oauth")]
    OAuthCallbackFailed { error: String },
    /// The rate limiter blocked an operation.
    RateLimited {
        /// A short label for the operation, e.g. `password_attempt`.
        operation: &'static str,
        identifier: String,
    },
    /// An email or text could not be delivered. `error` is the underlying
    /// cause; the user only sees a generic message.
    #[cfg(any(feature = "email", feature = "sms"))]
    DeliveryFailed {
        channel: DeliveryChannel,
        /// Address or number.
        recipient: String,
        error: String,
    },
}

/// The transport that failed.
#[cfg(any(feature = "email", feature = "sms"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryChannel {
    #[cfg(feature = "email")]
    Email,
    #[cfg(feature = "sms")]
    Sms,
}

/// Which code path rejected a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodeChannel {
    #[cfg(feature = "email")]
    EmailOtp,
    #[cfg(feature = "sms")]
    Sms,
    #[cfg(all(feature = "email", feature = "mfa"))]
    MfaEmail,
    #[cfg(all(feature = "sms", feature = "mfa"))]
    MfaSms,
    #[cfg(feature = "totp")]
    Totp,
    #[cfg(feature = "mfa")]
    RecoveryCode,
}

/// Joins an error's `source()` chain with `: `.
#[cfg(any(feature = "email", feature = "sms"))]
pub(crate) fn source_chain(err: &dyn std::error::Error) -> String {
    let mut parts = Vec::new();
    let mut current = err.source();
    while let Some(source) = current {
        parts.push(source.to_string());
        current = source.source();
    }
    if parts.is_empty() {
        "no further detail".to_string()
    } else {
        parts.join(": ")
    }
}

/// Receives every [`AuthEvent`]. Called synchronously on the request path.
pub trait AuthEventHandler: Send + Sync + std::fmt::Debug {
    fn on_event(&self, event: AuthEvent);
}

/// The default handler: logs successes at `info` and failures at `warn`
/// through [`tracing`].
#[derive(Debug, Clone, Copy)]
pub struct TracingEvents;

impl AuthEventHandler for TracingEvents {
    fn on_event(&self, event: AuthEvent) {
        match &event {
            AuthEvent::LoginSucceeded { user_id, method } => {
                tracing::info!(user_id, ?method, "login succeeded");
            }
            #[cfg(feature = "password")]
            AuthEvent::PasswordRejected { password_id } => {
                tracing::warn!(password_id, "password rejected");
            }
            AuthEvent::CodeRejected {
                channel,
                identifier,
            } => {
                tracing::warn!(?channel, identifier, "code rejected");
            }
            #[cfg(feature = "oauth")]
            AuthEvent::OAuthCallbackFailed { error } => {
                tracing::warn!(error, "oauth callback failed");
            }
            AuthEvent::RateLimited {
                operation,
                identifier,
            } => {
                tracing::warn!(operation, identifier, "rate limited");
            }
            #[cfg(any(feature = "email", feature = "sms"))]
            AuthEvent::DeliveryFailed {
                channel,
                recipient,
                error,
            } => {
                tracing::error!(?channel, recipient, error, "message delivery failed");
            }
            #[allow(unreachable_patterns)]
            _ => tracing::info!(?event, "auth event"),
        }
    }
}

//! App-supplied rate limiting for abusable operations.
//!
//! Authery deliberately does not ship a limiter implementation: the right
//! backing (in-memory, redis, the app's own store) and the right keys (client
//! IP, forwarded headers) are app decisions, and IP-keyed limiting is best done
//! in a tower layer around the router anyway. What the app layer *cannot* see is
//! which operations are auth-sensitive and which identifier they concern - so
//! that is what this hook provides: authery calls [`RateLimiter::check`] with
//! the operation and its identifier before doing the work, and refuses with
//! [`RateLimited`] when the limiter says no.

use chrono::Duration;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

/// The operation about to be performed, with the identifier it should be
/// keyed on. Non-exhaustive: new operations gain variants over time.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RateLimitOp<'a> {
    /// A password verification attempt (login, or signup against an existing
    /// user). Key of interest: the password id, to slow down guessing.
    PasswordAttempt { password_id: &'a str },
    /// An outgoing email challenge - login/signup/verify/reset links or codes.
    /// Key of interest: the address, to cap mail spam per recipient.
    EmailSend { address: &'a str },
    /// A one-time-code verification attempt. Key of interest: the address.
    /// Six-digit codes are guessable, so cap attempts tightly (the code is
    /// also single-use and short-lived).
    OtpAttempt { address: &'a str },
    /// A TOTP (authenticator-app) verification attempt, keyed on the user id
    /// in its string representation. Same guessability caveat as OtpAttempt.
    TotpAttempt { user_id: &'a str },
    /// An outgoing SMS. Key of interest: the number - SMS costs money, cap
    /// sends per recipient tightly.
    SmsSend { number: &'a str },
    /// An SMS code verification attempt. Same guessability caveat as
    /// OtpAttempt.
    SmsAttempt { number: &'a str },
}

/// Refusal returned by a limiter. `retry_after` is advisory and surfaced to the
/// client as a Retry-After header where the transport supports it.
#[derive(Debug, thiserror::Error)]
#[error("Rate limited. Try again later.")]
pub struct RateLimited {
    pub retry_after: Option<Duration>,
}

pub type RateLimitFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RateLimited>> + Send + 'a>>;

/// Consulted before abusable operations. Implement and register with
/// [`crate::config::AutheryConfig::with_rate_limiter`]. Return `Ok(())` to let
/// the operation proceed, `Err(RateLimited)` to refuse it.
///
/// Implementations should be cheap and infallible on the happy path - this
/// sits in front of every guarded operation.
pub trait RateLimiter: Debug + Send + Sync {
    fn check<'a>(&'a self, op: RateLimitOp<'a>) -> RateLimitFuture<'a>;
}

/// The default limiter: allows everything.
#[derive(Debug, Clone, Default)]
pub struct NoRateLimit;

impl RateLimiter for NoRateLimit {
    fn check<'a>(&'a self, _op: RateLimitOp<'a>) -> RateLimitFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

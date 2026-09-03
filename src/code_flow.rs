//! The shared skeleton of every one-time-code flow: generate, store and
//! deliver a code; rate-limit, consume and expiry-check it on the way back;
//! resolve the user behind the identifier. The email `otp`, `sms` and MFA
//! code factors implement [`CodeFlow`] (login/signup flows additionally
//! [`CodeLoginFlow`]) to fill in the channel-specific pieces.

use crate::codes::CodeGenerator;
use crate::core::CoreAuthery;
use crate::models::{Allow, AutheryCookies, Intent, LoginMethod, User, email::EmailChallenge};
use crate::ratelimit::{MaybeRateLimited, RateLimitOp, RateLimited};
use crate::store::AutheryStore;
use chrono::Utc;
use thiserror::Error;

/// One code-delivering channel: key namespace, rate-limit operations, code
/// generation and delivery.
pub(crate) trait CodeFlow {
    /// The delivery error. Parameterized over the store error for channels
    /// that send through store-aware machinery.
    type SendError<E: std::error::Error>: std::fmt::Debug + std::fmt::Display + MaybeRateLimited;

    /// The namespaced store key for a code, e.g. `otp:{identifier}:{code}`.
    fn challenge_key(identifier: &str, code: &str) -> String;

    /// The channel reported on
    /// [`AuthEvent::CodeRejected`](crate::events::AuthEvent::CodeRejected).
    fn rejected_channel() -> crate::events::CodeChannel;

    /// The login method recorded when a code from this channel verifies.
    fn login_method(identifier: String) -> LoginMethod;

    fn send_op(identifier: &str) -> RateLimitOp<'_>;

    fn attempt_op(identifier: &str) -> RateLimitOp<'_>;

    fn generator<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> &dyn CodeGenerator;

    fn challenge_lifetime<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> chrono::Duration;

    async fn deliver<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        to: &str,
        code: &str,
    ) -> Result<(), Self::SendError<S::Error>>;
}

/// A [`CodeFlow`] that serves logins and signups: allow-policy overrides and
/// user lookup/creation by the channel identifier.
pub(crate) trait CodeLoginFlow: CodeFlow {
    /// Whether the config offers this channel for logins at all.
    fn offer_login<S: AutheryStore, C: AutheryCookies>(_auth: &CoreAuthery<S, C>) -> bool {
        true
    }

    fn allow_login_override<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> Option<&Allow>;

    fn allow_signup_override<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
    ) -> Option<&Allow>;

    /// The user owning the identifier, and whether that credential admits
    /// logins.
    async fn lookup_user<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        identifier: &str,
    ) -> Result<Option<(S::User, bool)>, S::Error>;

    async fn create_user<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        identifier: &str,
    ) -> Result<S::User, S::Error>;
}

/// A [`CodeFlow`] usable as an MFA second factor.
#[cfg(feature = "mfa")]
pub(crate) trait MfaCodeFlow: CodeFlow {
    /// The verified contact this factor sends to, from the user's factors.
    fn factor_target(factors: crate::mfa::MfaFactors) -> Option<String>;
}

/// Rate-limit, code-generation, store or delivery failure while sending a
/// code.
#[derive(Debug, Error)]
pub enum SendCodeError<
    StoreError: std::error::Error,
    SendError: std::fmt::Debug + std::fmt::Display,
> {
    #[error(transparent)]
    RateLimited(RateLimited),
    /// Delivery failure; the cause is reported through
    /// [`AuthEvent::DeliveryFailed`](crate::events::AuthEvent::DeliveryFailed).
    #[error("Could not send the code, please try again later")]
    Send(SendError),
    #[error(transparent)]
    Store(StoreError),
}

impl<E: std::error::Error, SE: std::fmt::Debug + std::fmt::Display + MaybeRateLimited>
    MaybeRateLimited for SendCodeError<E, SE>
{
    fn rate_limited(&self) -> Option<&RateLimited> {
        match self {
            Self::RateLimited(limited) => Some(limited),
            Self::Send(inner) => inner.rate_limited(),
            Self::Store(_) => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum CodeInitError<
    StoreError: std::error::Error,
    SendError: std::fmt::Debug + std::fmt::Display,
> {
    #[error("{0} not allowed")]
    NotAllowed(Intent),
    /// Delivery failure; the cause is reported through
    /// [`AuthEvent::DeliveryFailed`](crate::events::AuthEvent::DeliveryFailed).
    #[error("Could not send the code, please try again later")]
    Send(SendError),
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    Store(StoreError),
}

impl<E: std::error::Error, SE: std::fmt::Debug + std::fmt::Display> From<SendCodeError<E, SE>>
    for CodeInitError<E, SE>
{
    fn from(err: SendCodeError<E, SE>) -> Self {
        match err {
            SendCodeError::RateLimited(limited) => Self::RateLimited(limited),
            SendCodeError::Send(inner) => Self::Send(inner),
            SendCodeError::Store(inner) => Self::Store(inner),
        }
    }
}

impl<E: std::error::Error, SE: std::fmt::Debug + std::fmt::Display + MaybeRateLimited>
    MaybeRateLimited for CodeInitError<E, SE>
{
    fn rate_limited(&self) -> Option<&RateLimited> {
        match self {
            Self::RateLimited(limited) => Some(limited),
            Self::Send(inner) => inner.rate_limited(),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum CodeVerifyError<StoreError: std::error::Error> {
    #[error("{0} not allowed")]
    NotAllowed(Intent),
    #[error("User already exists")]
    UserExists,
    #[error("User not found")]
    NoUser,
    #[error("Wrong or expired code")]
    WrongCode,
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    Store(#[from] StoreError),
}

crate::ratelimit::impl_maybe_rate_limited!(CodeVerifyError, RateLimited);

/// Rate-limit, store, or wrong/expired-code failure while consuming a
/// submitted code.
#[derive(Debug)]
pub(crate) enum ConsumeCodeError<StoreError: std::error::Error> {
    RateLimited(RateLimited),
    WrongCode,
    Store(StoreError),
}

impl<E: std::error::Error> From<ConsumeCodeError<E>> for CodeVerifyError<E> {
    fn from(err: ConsumeCodeError<E>) -> Self {
        match err {
            ConsumeCodeError::RateLimited(limited) => Self::RateLimited(limited),
            ConsumeCodeError::WrongCode => Self::WrongCode,
            ConsumeCodeError::Store(inner) => Self::Store(inner),
        }
    }
}

/// Failure resolving the user behind a verified identifier under an
/// [`Intent`].
#[derive(Debug, Error)]
pub enum ResolveUserError<StoreError: std::error::Error> {
    #[error("Not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error("User not found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<E: std::error::Error> From<ResolveUserError<E>> for CodeVerifyError<E> {
    fn from(err: ResolveUserError<E>) -> Self {
        match err {
            ResolveUserError::NotAllowed => Self::NotAllowed(Intent::LogIn),
            ResolveUserError::UserExists => Self::UserExists,
            ResolveUserError::NoUser => Self::NoUser,
            ResolveUserError::Store(inner) => Self::Store(inner),
        }
    }
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// The intent-appropriate allow gate for a channel.
    fn code_allowed<Ch: CodeLoginFlow>(&self, intent: Intent) -> bool {
        match intent {
            Intent::LogIn => {
                Ch::offer_login(self)
                    && self.login_allow(Ch::allow_login_override(self)) != &Allow::Never
            }
            Intent::SignUp => self.signup_allow(Ch::allow_signup_override(self)) != &Allow::Never,
        }
    }

    /// Send a login or signup code to the identifier. The generic error
    /// message on the verify side means this deliberately does not reveal
    /// whether a user exists.
    pub(crate) async fn code_init<Ch: CodeLoginFlow>(
        &self,
        identifier: String,
        next: Option<String>,
        intent: Intent,
    ) -> Result<(), CodeInitError<S::Error, Ch::SendError<S::Error>>> {
        if !self.code_allowed::<Ch>(intent) {
            return Err(CodeInitError::NotAllowed(intent));
        }

        Ok(self.send_code::<Ch>(identifier, next).await?)
    }

    /// Rate-limit, generate, store and deliver a code.
    pub(crate) async fn send_code<Ch: CodeFlow>(
        &self,
        identifier: String,
        next: Option<String>,
    ) -> Result<(), SendCodeError<S::Error, Ch::SendError<S::Error>>> {
        self.check_rate(Ch::send_op(&identifier))
            .await
            .map_err(SendCodeError::RateLimited)?;

        let code = Ch::generator(self).generate();
        // Store the code namespaced per identifier; deliver only the code.
        let key = Ch::challenge_key(&identifier, &code);

        let challenge = self
            .store
            .create_challenge(
                identifier,
                key,
                next,
                Utc::now() + Ch::challenge_lifetime(self),
            )
            .await
            .map_err(SendCodeError::Store)?;

        Ch::deliver(self, challenge.get_address(), &code)
            .await
            .map_err(SendCodeError::Send)
    }

    /// Rate-limit, consume and expiry-check a submitted code, emitting
    /// [`AuthEvent::CodeRejected`](crate::events::AuthEvent::CodeRejected) on
    /// a miss.
    pub(crate) async fn consume_code<Ch: CodeFlow>(
        &self,
        identifier: &str,
        code: &str,
    ) -> Result<S::EmailChallenge, ConsumeCodeError<S::Error>> {
        self.check_rate(Ch::attempt_op(identifier))
            .await
            .map_err(ConsumeCodeError::RateLimited)?;

        let reject = || {
            self.emit(crate::events::AuthEvent::CodeRejected {
                channel: Ch::rejected_channel(),
                identifier: identifier.to_string(),
            });
        };

        let Some(challenge) = self
            .store
            .consume_challenge(Ch::challenge_key(identifier, code))
            .await
            .map_err(ConsumeCodeError::Store)?
        else {
            reject();
            return Err(ConsumeCodeError::WrongCode);
        };

        if challenge.get_expires() < Utc::now() {
            reject();
            return Err(ConsumeCodeError::WrongCode);
        }

        Ok(challenge)
    }

    /// Verify a login or signup code and log the user in - creating them
    /// first when signup-on-login (or logging in when login-on-signup) is
    /// allowed.
    pub(crate) async fn code_verify<Ch: CodeLoginFlow>(
        self,
        identifier: &str,
        code: &str,
        intent: Intent,
    ) -> Result<(Self, Option<String>), CodeVerifyError<S::Error>> {
        if !self.code_allowed::<Ch>(intent) {
            return Err(CodeVerifyError::NotAllowed(intent));
        }

        let challenge = self.consume_code::<Ch>(identifier, code).await?;

        let user = self
            .resolve_user::<Ch>(challenge.get_address(), intent)
            .await?;

        Ok((
            self.log_in(
                Ch::login_method(challenge.get_address().to_owned()),
                &user.get_id(),
            )
            .await
            .map_err(CodeVerifyError::Store)?,
            challenge.get_next().clone(),
        ))
    }

    /// The user behind a proven identifier: an existing user whose credential
    /// admits logins, or a fresh one when the intent and policy allow
    /// creation.
    pub(crate) async fn resolve_user<Ch: CodeLoginFlow>(
        &self,
        identifier: &str,
        intent: Intent,
    ) -> Result<S::User, ResolveUserError<S::Error>> {
        let existing = Ch::lookup_user(self, identifier)
            .await
            .map_err(ResolveUserError::Store)?;

        match intent {
            Intent::LogIn => {
                let signup_on_login =
                    self.signup_allow(Ch::allow_signup_override(self)) == &Allow::OnEither;

                match existing {
                    Some((user, true)) => Ok(user),
                    Some(_) => Err(ResolveUserError::NotAllowed),
                    None if signup_on_login => Ch::create_user(self, identifier)
                        .await
                        .map_err(ResolveUserError::Store),
                    None => Err(ResolveUserError::NoUser),
                }
            }
            Intent::SignUp => {
                let login_on_signup =
                    self.login_allow(Ch::allow_login_override(self)) == &Allow::OnEither;

                match existing {
                    Some((user, can_login)) if login_on_signup && can_login => Ok(user),
                    Some(_) if login_on_signup => Err(ResolveUserError::NotAllowed),
                    Some(_) => Err(ResolveUserError::UserExists),
                    None => Ch::create_user(self, identifier)
                        .await
                        .map_err(ResolveUserError::Store),
                }
            }
        }
    }
}

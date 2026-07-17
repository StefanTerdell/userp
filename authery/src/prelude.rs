//! Includes all types and traits (but not individual models) defined in the crate.
//! Something missing? This is a bug. Please file an issue in the project repo.

pub use crate::routes::Routes;
#[cfg(feature = "email")]
pub use crate::routes::email::*;
#[cfg(feature = "oauth")]
pub use crate::routes::oauth::{OAuthRoutes, actions::*, callbacks::*};
pub use crate::routes::pages::*;
#[cfg(feature = "password")]
pub use crate::routes::password::*;
#[cfg(feature = "user")]
pub use crate::routes::user::*;

#[cfg(feature = "axum")]
pub use crate::axum::{
    AxumAuthery,
    cookies::AxumAutheryCookies,
    router::{AxumRouter, with_cookie_layer},
};

#[cfg(all(feature = "email", feature = "password"))]
pub use crate::email::reset::*;
#[cfg(all(feature = "email", feature = "password"))]
pub use crate::password::PasswordReset;

#[cfg(feature = "email")]
pub use crate::email::{
    EmailConfig, SendEmailChallengeError, SmtpSettings, login::*, signup::*, verify::*,
};

#[cfg(feature = "password")]
pub use crate::password::{PasswordConfig, hasher::*, login::*, signup::*};

#[cfg(feature = "oauth")]
pub use crate::oauth::{
    OAuthCallbackError, OAuthConfig, OAuthFlow, OAuthGenericCallbackError, OAuthProviderResolver,
    OAuthProviders, ProviderResolverFuture, RefreshInitResult,
    client::*,
    link::*,
    login::*,
    provider::{
        ExchangeResult, OAuthProvider, custom::*, discord::*, facebook::*, github::*, gitlab::*,
        google::*, linkedin::*, microsoft::*, oidc::*, slack::*, spotify::*, twitch::*, x::*,
    },
    refresh::*,
    signup::*,
};

#[cfg(feature = "pages")]
pub use crate::pages::*;

#[cfg(feature = "totp")]
pub use crate::models::TotpCredential;
#[cfg(feature = "email")]
pub use crate::models::email::*;
#[cfg(feature = "oauth")]
pub use crate::models::oauth::*;
pub use crate::models::{Allow, AutheryCookies, LoginMethod, LoginMethodRules, LoginSession, User};

#[cfg(feature = "mfa")]
pub use crate::mfa::{MfaError, MfaFactors, MfaPolicy};
pub use crate::ratelimit::{NoRateLimit, RateLimitFuture, RateLimitOp, RateLimited, RateLimiter};
#[cfg(feature = "mfa")]
pub use crate::routes::mfa::MfaRoutes;
#[cfg(feature = "webauthn")]
pub use crate::routes::webauthn::WebauthnRoutes;
#[cfg(feature = "totp")]
pub use crate::totp::{TotpConfig, TotpEnrollment, TotpError};
#[cfg(feature = "webauthn")]
pub use crate::webauthn::{WebauthnConfig, WebauthnLoginError, WebauthnRegisterError};
pub use crate::{Authery, config::*, constants::*, core::*, store::*};

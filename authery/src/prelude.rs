//! Includes all types and traits (but not individual models) defined in the crate.
//! Something missing? This is a bug. Please file an issue in the project repo.

pub use crate::routes::pages::*;
#[cfg(feature = "user")]
pub use crate::routes::user::*;
pub use crate::routes::Routes;
#[cfg(feature = "email")]
pub use crate::routes::email::*;
#[cfg(feature = "oauth")]
pub use crate::routes::oauth::{actions::*, callbacks::*, OAuthRoutes};
#[cfg(feature = "password")]
pub use crate::routes::password::*;

#[cfg(feature = "axum")]
pub use crate::axum::{
    cookies::AxumAutheryCookies,
    router::{with_cookie_layer, AxumRouter},
    AxumAuthery,
};

#[cfg(all(feature = "email", feature = "password"))]
pub use crate::email::reset::*;
#[cfg(all(feature = "email", feature = "password"))]
pub use crate::password::PasswordReset;

#[cfg(feature = "email")]
pub use crate::email::{
    login::*, signup::*, verify::*, EmailConfig, SendEmailChallengeError, SmtpSettings,
};

#[cfg(feature = "password")]
pub use crate::password::{hasher::*, login::*, signup::*, PasswordConfig};

#[cfg(feature = "oauth")]
pub use crate::oauth::{
    client::*,
    link::*,
    login::*,
    provider::{
        custom::*, discord::*, facebook::*, github::*, gitlab::*, google::*, linkedin::*,
        microsoft::*, oidc::*, slack::*, spotify::*, twitch::*, x::*, ExchangeResult,
        OAuthProvider,
    },
    refresh::*,
    signup::*,
    OAuthCallbackError, OAuthConfig, OAuthFlow, OAuthGenericCallbackError, OAuthProviderResolver,
    OAuthProviders, ProviderResolverFuture, RefreshInitResult,
};

#[cfg(feature = "pages")]
pub use crate::pages::*;

#[cfg(feature = "email")]
pub use crate::models::email::*;
#[cfg(feature = "oauth")]
pub use crate::models::oauth::*;
pub use crate::models::{
    Allow, AutheryCookies, LoginMethod, LoginMethodRules, LoginSession, User,
};

#[cfg(feature = "mfa")]
pub use crate::mfa::{MfaError, MfaFactors, MfaPolicy};
#[cfg(feature = "mfa")]
pub use crate::routes::mfa::MfaRoutes;
pub use crate::ratelimit::{NoRateLimit, RateLimitFuture, RateLimitOp, RateLimited, RateLimiter};
#[cfg(feature = "webauthn")]
pub use crate::routes::webauthn::WebauthnRoutes;
#[cfg(feature = "webauthn")]
pub use crate::webauthn::{WebauthnConfig, WebauthnLoginError, WebauthnRegisterError};
pub use crate::{config::*, constants::*, core::*, store::*, Authery};

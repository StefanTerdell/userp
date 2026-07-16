#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "oauth")]
pub mod oauth;

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use uuid::Uuid;

/// An entity ID. IDs must roundtrip through their string representation,
/// which is used for cookies and other wire formats.
pub trait Id:
    Clone + std::fmt::Debug + Display + std::str::FromStr + PartialEq + Send + Sync + 'static
{
    /// Generate a new, unique ID. Must be unguessable (i.e. backed by a CSPRNG),
    /// since IDs generated for sessions act as bearer tokens.
    fn new_random() -> Self;
}

impl Id for Uuid {
    fn new_random() -> Self {
        Uuid::new_v4()
    }
}

/// Used to control if the method (like email, password, oauth) or specific oauth provider
/// can be used for either logging in, signing up, both, or none
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
pub enum Allow {
    /// The method or provider can never be used for either login or signup
    Never,
    /// The method or provider can only be used for its main configured case, and not the other (login vs. signup)
    ///
    /// Meaning:
    /// - If the user tries to log in before signing up, a "user not found" error will typically be returned
    /// - If the user tries to sign up but already has an account, a "user conflict" error will typically be returned
    OnSelf,
    /// The method or provider can be used interchangably for signup and login
    ///
    /// Meaning:
    /// - If the user tries to log in before signing up, the signup flow is used
    /// - If the user tries to sign up but already has an account, the login flow is used
    OnEither,
}

/// Describes what method was used to authenticate the login session
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    #[cfg(feature = "password")]
    /// The login session was created using the Password method
    Password,
    #[cfg(all(feature = "password", feature = "email"))]
    /// The login session was created only to reset the users password
    /// Only available when both the email and the password features are enabled
    PasswordReset {
        /// The email-address used to create the PasswordReset session
        address: String,
    },
    #[cfg(feature = "email")]
    /// The login session was created using the Email method
    Email {
        /// The email-address used to create the Email session
        address: String,
    },
    #[cfg(feature = "otp")]
    /// The login session was created with a one-time code sent by email
    Otp {
        /// The email-address the code was sent to
        address: String,
    },
    #[cfg(feature = "webauthn")]
    /// The login session was created with a passkey/authenticator
    Webauthn {
        /// The hex-encoded credential id of the passkey used
        credential_id: String,
    },
    #[cfg(feature = "mfa")]
    /// A first factor succeeded but the MFA policy demands a second one.
    /// Sessions with this method are NOT logged in - they can only be used to
    /// complete the second factor, which replaces them with [`LoginMethod::Mfa`].
    MfaPending {
        /// The first factor that already succeeded
        first: Box<LoginMethod>,
    },
    #[cfg(feature = "mfa")]
    /// The login session was created by completing two factors
    Mfa {
        /// The first factor
        first: Box<LoginMethod>,
        /// The second factor
        second: Box<LoginMethod>,
    },
    #[cfg(feature = "oauth")]
    /// The login session was created using the Oauth method
    OAuth {
        /// The specific OAuth token ID associated with the session,
        /// in its string representation
        token_id: String,
    },
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:#?}"))
    }
}

/// App-level policy over login methods, e.g. "accessing this tenant requires
/// MFA" or "no password sessions here". Authery does not enforce these
/// anywhere itself - they are a building block for gating your own routes:
///
/// ```ignore
/// let rules = LoginMethodRules { require_mfa: true, ..Default::default() };
/// if !rules.satisfies(&session.get_method()) {
///     return Redirect::to("/login/mfa");
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginMethodRules {
    /// Only two-factor sessions ([`LoginMethod::Mfa`]) - or single-factor
    /// passkeys, which prove possession plus user verification - satisfy the
    /// rules.
    pub require_mfa: bool,
    /// Whether password-first sessions satisfy the rules.
    pub allow_password: bool,
    /// Whether emailed link/code-first sessions satisfy the rules.
    pub allow_email: bool,
}

impl Default for LoginMethodRules {
    fn default() -> Self {
        Self {
            require_mfa: false,
            allow_password: true,
            allow_email: true,
        }
    }
}

impl LoginMethodRules {
    /// Whether a session's login method satisfies the rules. The `allow_*`
    /// rules judge the first factor; `require_mfa` accepts two-factor
    /// sessions and single-factor passkeys.
    pub fn satisfies(&self, method: &LoginMethod) -> bool {
        #[cfg(feature = "mfa")]
        let (first, is_mfa) = match method {
            LoginMethod::Mfa { first, .. } => (first.as_ref(), true),
            method => (method, false),
        };
        #[cfg(not(feature = "mfa"))]
        let (first, is_mfa) = (method, false);

        if self.require_mfa {
            #[cfg(feature = "webauthn")]
            let strong_single = matches!(first, LoginMethod::Webauthn { .. });
            #[cfg(not(feature = "webauthn"))]
            let strong_single = false;

            if !is_mfa && !strong_single {
                return false;
            }
        }

        match first {
            #[cfg(feature = "password")]
            LoginMethod::Password => self.allow_password,
            #[cfg(feature = "email")]
            LoginMethod::Email { .. } => self.allow_email,
            #[cfg(feature = "otp")]
            LoginMethod::Otp { .. } => self.allow_email,
            _ => true,
        }
    }
}

pub trait LoginSession: Send + Sync + Sized {
    type Id: Id;
    type UserId: Id;

    fn get_id(&self) -> Self::Id;
    fn get_user_id(&self) -> Self::UserId;
    fn get_method(&self) -> LoginMethod;

    /// When this session expires. Also used to order sessions by age when
    /// enforcing the concurrent-session cap (all sessions share one lifetime,
    /// so earliest expiry means oldest session).
    fn get_expires(&self) -> chrono::DateTime<chrono::Utc>;

    /// Whether this session has passed its expiry. The core treats an expired
    /// session as logged-out and evicts it from the store on next use.
    fn is_expired(&self) -> bool {
        self.get_expires() < chrono::Utc::now()
    }
}

pub trait User: Send + Sync + Sized {
    type Id: Id;

    fn get_id(&self) -> Self::Id;
    #[cfg(feature = "password")]
    fn get_password_hash(&self) -> Option<String>;
}

pub trait AutheryCookies {
    fn add(&mut self, key: &str, value: &str);
    fn get(&self, key: &str) -> Option<String>;
    fn remove(&mut self, key: &str);
    fn list_encoded(&self) -> Vec<String>;
}

//! The single table of everything `router()` mounts. Each row is one
//! (method, path) pair; the macro expands it into the `Endpoint` enum and
//! every per-endpoint match, so nothing can be mounted without a row and no
//! row can go unmounted.

use crate::config::AutheryConfig;
use crate::routes::Routes;
use crate::store::AutheryStore;
use axum::{extract::FromRef, http::Method, routing::MethodRouter};

#[cfg(feature = "openapi")]
use crate::openapi::{Describe, Operation};
#[cfg(feature = "openapi")]
use std::collections::BTreeMap;

/// The description authery gives an opaque WebAuthn credential body.
#[cfg(feature = "openapi")]
pub(crate) const CREDENTIAL: &str = "W3C PublicKeyCredential JSON";
/// And the ceremony options it hands back.
#[cfg(feature = "openapi")]
pub(crate) const CHALLENGE: &str = "W3C credential creation or request options JSON";

macro_rules! method_router {
    (get, $handler:expr) => {
        axum::routing::get($handler)
    };
    (post, $handler:expr) => {
        axum::routing::post($handler)
    };
}

/// The same table, routed through aide so the operations are documented.
#[cfg(feature = "aide")]
macro_rules! api_method_router {
    (get, $handler:expr, $transform:expr) => {
        ::aide::axum::routing::get_with($handler, $transform)
    };
    (post, $handler:expr, $transform:expr) => {
        ::aide::axum::routing::post_with($handler, $transform)
    };
}

/// The response shape an endpoint produces, keyed off its row. Each variant
/// is one honest list: an operation documents a status only when its handler
/// can actually answer with it.
#[cfg(feature = "openapi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseSet {
    /// Form-driven flow POST: 303 for browsers, 200/422 JSON under Accept.
    Flow,
    /// A flow whose redirect never carries `?error=`, so there is no 422.
    FlowDone,
    /// [`Self::Flow`] on an operation that answers `401` without a session.
    GuardedFlow,
    /// [`Self::FlowDone`] on an operation that answers `401` without a session.
    GuardedFlowDone,
    /// [`Self::GuardedFlowDone`] plus the `400` for an unparseable id.
    GuardedIdFlow,
    /// The OAuth refresh POST: a guarded flow that also 400s on a bad id and
    /// 404s on a token that is not the caller's.
    OAuthRefresh,
    /// HTML page GET.
    Page,
    /// A POST that renders a page directly - the payload is too large to
    /// survive a redirect - or redirects when it cannot.
    PageAction,
    /// Ceremony start: 200 opaque challenge JSON.
    WebauthnChallenge,
    /// Ceremony finish: 200 FlowResult, 401 ApiError.
    WebauthnFinish,
    /// 200 or 401, no body.
    Status,
    /// A GET that always redirects.
    Redirect,
}

/// One documented response: the status it answers with, the body shape and
/// the words describing it. [`ResponseSet::responses`] is the single source
/// of truth both describers - [`Endpoint::describe`] for authery's own
/// document and `transform_aide` for aide's - read, so the two cannot drift.
#[cfg(feature = "openapi")]
pub(crate) struct ResponseDoc {
    pub(crate) status: Status,
    pub(crate) body: Body,
    pub(crate) description: &'static str,
    /// Whether this response carries `X-Auth-Token`, on an operation that
    /// can establish a new session.
    pub(crate) token: bool,
}

/// A response status: one code, or a whole class like `4XX`.
#[cfg(feature = "openapi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Code(u16),
    Range(u16),
}

#[cfg(feature = "openapi")]
impl Status {
    /// The key OpenAPI files it under.
    pub(crate) fn label(&self) -> String {
        match self {
            Status::Code(code) => code.to_string(),
            Status::Range(class) => format!("{class}XX"),
        }
    }
}

/// The body shape of a documented response.
#[cfg(feature = "openapi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Body {
    /// Nothing worth describing: a redirect, or a bare status.
    None,
    FlowResult,
    FlowError,
    ApiError,
    /// The rendered page.
    Html,
    /// The opaque W3C ceremony options.
    Challenge,
}

/// The store's own refusal, on every operation.
#[cfg(feature = "openapi")]
pub(crate) const STORE_REFUSED: ResponseDoc = ResponseDoc {
    status: Status::Range(4),
    body: Body::ApiError,
    description: "The store refused the request and chose to say why.",
    token: false,
};

/// The catch-all, on every operation.
#[cfg(feature = "openapi")]
pub(crate) const INTERNAL_ERROR: ResponseDoc = ResponseDoc {
    status: Status::Code(500),
    body: Body::ApiError,
    description: "Internal server error.",
    token: false,
};

// The individual responses the sets below are assembled from.

/// The browser redirect on an operation that can be refused.
#[cfg(feature = "openapi")]
const SEE_OTHER: ResponseDoc = ResponseDoc {
    status: Status::Code(303),
    body: Body::None,
    description: "Browser clients: redirect to the next page, with `?error=` on refusal.",
    token: true,
};

/// The browser redirect on an operation that cannot be refused.
#[cfg(feature = "openapi")]
const SEE_OTHER_DONE: ResponseDoc = ResponseDoc {
    status: Status::Code(303),
    body: Body::None,
    description: "Browser clients: redirect to the next page.",
    token: true,
};

#[cfg(feature = "openapi")]
const FLOW_OK: ResponseDoc = ResponseDoc {
    status: Status::Code(200),
    body: Body::FlowResult,
    description: "JSON clients: the step succeeded.",
    token: true,
};

#[cfg(feature = "openapi")]
const FLOW_REFUSED: ResponseDoc = ResponseDoc {
    status: Status::Code(422),
    body: Body::FlowError,
    description: "JSON clients: the step was refused.",
    token: false,
};

/// What a guarded operation answers without a session; the body carries the
/// [`crate::axum::response::NOT_LOGGED_IN`] message.
#[cfg(feature = "openapi")]
const UNAUTHORIZED: ResponseDoc = ResponseDoc {
    status: Status::Code(401),
    body: Body::ApiError,
    description: "Not logged in.",
    token: false,
};

#[cfg(feature = "openapi")]
const MALFORMED_ID: ResponseDoc = ResponseDoc {
    status: Status::Code(400),
    body: Body::ApiError,
    description: "The submitted id could not be parsed.",
    token: false,
};

#[cfg(feature = "openapi")]
const NO_SUCH_TOKEN: ResponseDoc = ResponseDoc {
    status: Status::Code(404),
    body: Body::ApiError,
    description: "No OAuth token with that id belongs to the caller.",
    token: false,
};

#[cfg(feature = "openapi")]
const PAGE: ResponseDoc = ResponseDoc {
    status: Status::Code(200),
    body: Body::Html,
    description: "The page.",
    token: false,
};

/// A page-rendering POST that could not render: not logged in, or refused.
#[cfg(feature = "openapi")]
const PAGE_REDIRECT: ResponseDoc = ResponseDoc {
    status: Status::Code(303),
    body: Body::None,
    description: "Browser clients: a redirect instead of a page, when the step was refused.",
    token: false,
};

#[cfg(feature = "openapi")]
const FLOW: &[ResponseDoc] = &[SEE_OTHER, FLOW_OK, FLOW_REFUSED];
#[cfg(feature = "openapi")]
const FLOW_DONE: &[ResponseDoc] = &[SEE_OTHER_DONE, FLOW_OK];
#[cfg(feature = "openapi")]
const GUARDED_FLOW: &[ResponseDoc] = &[SEE_OTHER, FLOW_OK, FLOW_REFUSED, UNAUTHORIZED];
#[cfg(feature = "openapi")]
const GUARDED_FLOW_DONE: &[ResponseDoc] = &[SEE_OTHER_DONE, FLOW_OK, UNAUTHORIZED];
#[cfg(feature = "openapi")]
const GUARDED_ID_FLOW: &[ResponseDoc] = &[SEE_OTHER_DONE, FLOW_OK, UNAUTHORIZED, MALFORMED_ID];
#[cfg(feature = "openapi")]
const OAUTH_REFRESH: &[ResponseDoc] = &[
    SEE_OTHER,
    FLOW_OK,
    FLOW_REFUSED,
    UNAUTHORIZED,
    MALFORMED_ID,
    NO_SUCH_TOKEN,
];
#[cfg(feature = "openapi")]
const PAGE_SET: &[ResponseDoc] = &[PAGE];
#[cfg(feature = "openapi")]
const PAGE_ACTION: &[ResponseDoc] = &[PAGE, PAGE_REDIRECT];
#[cfg(feature = "openapi")]
const WEBAUTHN_CHALLENGE: &[ResponseDoc] = &[
    ResponseDoc {
        status: Status::Code(200),
        body: Body::Challenge,
        description: "The challenge to pass to `navigator.credentials`.",
        token: false,
    },
    ResponseDoc {
        status: Status::Code(400),
        body: Body::ApiError,
        description: "No ceremony could be started.",
        token: false,
    },
];
#[cfg(feature = "openapi")]
const WEBAUTHN_FINISH: &[ResponseDoc] = &[
    ResponseDoc {
        status: Status::Code(200),
        body: Body::FlowResult,
        description: "The ceremony completed.",
        token: true,
    },
    ResponseDoc {
        status: Status::Code(401),
        body: Body::ApiError,
        description: "The credential was rejected.",
        token: false,
    },
];
#[cfg(feature = "openapi")]
const STATUS: &[ResponseDoc] = &[
    ResponseDoc {
        status: Status::Code(200),
        body: Body::None,
        description: "Logged in.",
        token: false,
    },
    ResponseDoc {
        status: Status::Code(401),
        body: Body::None,
        description: "Not logged in.",
        token: false,
    },
];

#[cfg(feature = "openapi")]
impl ResponseSet {
    /// Whether this is a page-class shape: HTML meant for a browser, of no
    /// use to an API client, so it is left out of the document unless
    /// [`crate::openapi::OpenApiOptions::with_pages`] asks for it.
    pub(crate) fn is_page(&self) -> bool {
        matches!(self, ResponseSet::Page | ResponseSet::PageAction)
    }

    /// The responses this shape documents, before [`STORE_REFUSED`] and
    /// [`INTERNAL_ERROR`], which every operation adds.
    pub(crate) fn responses(&self) -> &'static [ResponseDoc] {
        match self {
            // A redirect endpoint answers exactly as a flow POST does.
            ResponseSet::Flow | ResponseSet::Redirect => FLOW,
            ResponseSet::FlowDone => FLOW_DONE,
            ResponseSet::GuardedFlow => GUARDED_FLOW,
            ResponseSet::GuardedFlowDone => GUARDED_FLOW_DONE,
            ResponseSet::GuardedIdFlow => GUARDED_ID_FLOW,
            ResponseSet::OAuthRefresh => OAUTH_REFRESH,
            ResponseSet::Page => PAGE_SET,
            ResponseSet::PageAction => PAGE_ACTION,
            ResponseSet::WebauthnChallenge => WEBAUTHN_CHALLENGE,
            ResponseSet::WebauthnFinish => WEBAUTHN_FINISH,
            ResponseSet::Status => STATUS,
        }
    }
}

macro_rules! http_method {
    (get) => {
        Method::GET
    };
    (post) => {
        Method::POST
    };
}

/// Row shape:
/// `Variant => method, "Tag", "operation_id", "Summary", ResponseSet::X, secured, establishes_session, routes.a.b, module::handler`
///
/// `secured` is whether the operation requires a session (the security
/// requirement it documents); `establishes_session` is whether it can hand
/// back a NEW one, which is what the cookie layer keys `X-Auth-Token` on.
/// They are independent: an MFA completion POST needs the pending session
/// AND rotates it into a real one.
macro_rules! endpoints {
    ($(
        $(#[$cfg:meta])*
        $variant:ident => $method:ident, $tag:literal, $name:literal, $summary:literal, $set:path, $secured:literal, $establishes:literal, routes.$($path:ident).+, $($handler:ident)::+
    );+ $(;)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub(crate) enum Endpoint {
            $( $(#[$cfg])* $variant, )+
        }

        impl Endpoint {
            pub(crate) fn all() -> Vec<Endpoint> {
                vec![ $( $(#[$cfg])* Endpoint::$variant, )+ ]
            }

            pub(crate) fn name(&self) -> &'static str {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => $name, )+
                }
            }

            pub(crate) fn tag(&self) -> &'static str {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => $tag, )+
                }
            }

            pub(crate) fn method(&self) -> Method {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => http_method!($method), )+
                }
            }

            #[cfg(feature = "openapi")]
            pub(crate) fn summary(&self) -> &'static str {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => $summary, )+
                }
            }

            #[cfg(feature = "openapi")]
            pub(crate) fn response_set(&self) -> ResponseSet {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => $set, )+
                }
            }

            #[cfg(feature = "openapi")]
            pub(crate) fn secured(&self) -> bool {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => $secured, )+
                }
            }

            /// Whether a successful call can hand back a NEW session, and so
            /// carry `X-Auth-Token`. Keyed off its own column rather than
            /// inferred from [`Self::secured`]: the MFA completion POSTs
            /// require a pending session and still rotate it.
            #[cfg(feature = "openapi")]
            pub(crate) fn establishes_session(&self) -> bool {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => $establishes, )+
                }
            }

            pub(crate) fn path<'r>(&self, routes: &'r Routes<String>) -> &'r str {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => routes.$($path).+.as_str(), )+
                }
            }

            pub(crate) fn handler<St, S>(&self) -> MethodRouter<S>
            where
                AutheryConfig: FromRef<S>,
                S: Send + Sync + Clone + 'static,
                St: AutheryStore + FromRef<S> + Send + Sync + 'static,
            {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => method_router!($method, $($handler)::+::<St>), )+
                }
            }

            /// The handler wired through aide's typed routing, with the
            /// operation described by [`Endpoint::transform_aide`]. `bearer`
            /// is the config's `bearer_auth` setting.
            #[cfg(feature = "aide")]
            pub(crate) fn api_handler<St, S>(&self, bearer: bool) -> ::aide::axum::routing::ApiMethodRouter<S>
            where
                AutheryConfig: FromRef<S>,
                S: Send + Sync + Clone + 'static,
                St: AutheryStore + FromRef<S> + Send + Sync + 'static,
            {
                match self {
                    $( $(#[$cfg])* Endpoint::$variant => api_method_router!(
                        $method,
                        $($handler)::+::<St>,
                        |op| self.transform_aide(bearer, op)
                    ), )+
                }
            }
        }
    };
}

endpoints! {
    Logout => post, "Session", "logout", "Log out", ResponseSet::FlowDone, true, false, routes.logout, super::post_user_logout;
    VerifySession => get, "Session", "verify_session", "Check whether the caller is logged in", ResponseSet::Status, true, false, routes.user_verify_session, super::get_user_verify_session;

    #[cfg(feature = "pages")]
    LoginPage => get, "Pages", "login_page", "Render the login page", ResponseSet::Page, false, false, routes.pages.login, super::pages::get_login;
    #[cfg(feature = "pages")]
    SignupPage => get, "Pages", "signup_page", "Render the signup page", ResponseSet::Page, false, false, routes.pages.signup, super::pages::get_signup;
    #[cfg(feature = "pages")]
    PausedPage => get, "Pages", "paused_page", "Render the rate-limit page", ResponseSet::Page, false, false, routes.pages.paused, super::pages::get_paused;
    #[cfg(all(feature = "pages", feature = "email"))]
    EmailSentPage => get, "Pages", "email_sent_page", "Render the check-your-inbox page", ResponseSet::Page, false, false, routes.pages.email_sent, super::pages::get_email_sent;
    #[cfg(all(feature = "pages", feature = "email"))]
    EmailExpiredPage => get, "Pages", "email_expired_page", "Render the expired-link page", ResponseSet::Page, false, false, routes.pages.email_expired, super::pages::get_email_expired;
    #[cfg(all(feature = "pages", feature = "email", feature = "password"))]
    PasswordSendResetPage => get, "Pages", "password_send_reset_page", "Render the request-a-reset page", ResponseSet::Page, false, false, routes.pages.password_send_reset, super::pages::get_password_send_reset;
    #[cfg(all(feature = "pages", feature = "email", feature = "password"))]
    PasswordResetPage => get, "Pages", "password_reset_page", "Render the choose-a-new-password page", ResponseSet::Page, false, false, routes.pages.password_reset, super::pages::get_password_reset;
    #[cfg(all(feature = "pages", feature = "user"))]
    UserPage => get, "Pages", "user_page", "Render the account page", ResponseSet::Page, true, false, routes.pages.user, super::pages::get_user;
    #[cfg(all(feature = "pages", feature = "mfa"))]
    LoginMfaPage => get, "Pages", "login_mfa_page", "Render the second-factor page", ResponseSet::Page, true, false, routes.mfa.login_mfa, super::pages::get_login_mfa;
    #[cfg(all(feature = "pages", feature = "sms"))]
    LoginSmsPage => get, "Pages", "login_sms_page", "Render the texted-code login page", ResponseSet::Page, false, false, routes.sms.login_sms, super::pages::get_login_sms;
    #[cfg(all(feature = "pages", feature = "sms"))]
    SignupSmsPage => get, "Pages", "signup_sms_page", "Render the texted-code signup page", ResponseSet::Page, false, false, routes.sms.signup_sms, super::pages::get_signup_sms;
    #[cfg(all(feature = "pages", feature = "email"))]
    LoginOtpPage => get, "Pages", "login_otp_page", "Render the emailed-code login page", ResponseSet::Page, false, false, routes.email.login_otp, super::pages::get_login_otp;
    #[cfg(all(feature = "pages", feature = "email"))]
    SignupOtpPage => get, "Pages", "signup_otp_page", "Render the emailed-code signup page", ResponseSet::Page, false, false, routes.email.signup_otp, super::pages::get_signup_otp;

    #[cfg(feature = "user")]
    UserDelete => post, "User", "user_delete", "Delete the account", ResponseSet::GuardedFlowDone, true, false, routes.user.user_delete, super::user::post_user_delete;
    #[cfg(feature = "user")]
    UserSessionDelete => post, "User", "user_session_delete", "End one session", ResponseSet::GuardedIdFlow, true, false, routes.user.user_session_delete, super::user::post_user_session_delete;
    #[cfg(feature = "user")]
    UserSessionDeleteOthers => post, "User", "user_session_delete_others", "End every other session", ResponseSet::GuardedFlowDone, true, false, routes.user.user_session_delete_others, super::user::post_user_session_delete_others;
    #[cfg(all(feature = "user", feature = "password"))]
    UserPasswordSet => post, "User", "user_password_set", "Set the password", ResponseSet::GuardedFlow, true, false, routes.user.user_password_set, super::user::post_user_password_set;
    #[cfg(all(feature = "user", feature = "password"))]
    UserPasswordDelete => post, "User", "user_password_delete", "Remove the password", ResponseSet::GuardedFlowDone, true, false, routes.user.user_password_delete, super::user::post_user_password_delete;
    #[cfg(all(feature = "user", feature = "oauth"))]
    UserOAuthDelete => post, "User", "user_oauth_delete", "Unlink an OAuth account", ResponseSet::GuardedIdFlow, true, false, routes.user.user_oauth_delete, super::user::post_user_oauth_delete;
    #[cfg(all(feature = "user", feature = "totp"))]
    UserTotpConfirm => post, "User", "user_totp_confirm", "Confirm authenticator enrollment", ResponseSet::Flow, true, false, routes.user.user_totp_confirm, super::user::post_user_totp_confirm;
    #[cfg(all(feature = "user", feature = "totp"))]
    UserTotpDisable => post, "User", "user_totp_disable", "Disable the authenticator app", ResponseSet::Flow, true, false, routes.user.user_totp_disable, super::user::post_user_totp_disable;
    #[cfg(all(feature = "user", feature = "totp", feature = "pages"))]
    UserTotpEnroll => post, "User", "user_totp_enroll", "Begin authenticator enrollment", ResponseSet::PageAction, true, false, routes.user.user_totp_enroll, super::user::post_user_totp_enroll;
    #[cfg(all(feature = "user", feature = "mfa", feature = "pages"))]
    UserRecoveryCodes => post, "User", "user_recovery_codes", "Generate a fresh batch of recovery codes", ResponseSet::PageAction, true, false, routes.user.user_recovery_codes, super::user::post_user_recovery_codes;
    #[cfg(all(feature = "user", feature = "email"))]
    UserEmailAdd => post, "User", "user_email_add", "Add an email address", ResponseSet::GuardedFlowDone, true, false, routes.user.user_email_add, super::user::post_user_email_add;
    #[cfg(all(feature = "user", feature = "email"))]
    UserEmailDelete => post, "User", "user_email_delete", "Remove an email address", ResponseSet::GuardedFlowDone, true, false, routes.user.user_email_delete, super::user::post_user_email_delete;
    #[cfg(all(feature = "user", feature = "email"))]
    UserEmailEnableLogin => post, "User", "user_email_enable_login", "Allow logging in with an address", ResponseSet::GuardedFlow, true, false, routes.user.user_email_enable_login, super::user::post_user_email_enable_login;
    #[cfg(all(feature = "user", feature = "email"))]
    UserEmailDisableLogin => post, "User", "user_email_disable_login", "Stop allowing logging in with an address", ResponseSet::GuardedFlowDone, true, false, routes.user.user_email_disable_login, super::user::post_user_email_disable_login;

    #[cfg(feature = "oauth")]
    LoginOAuth => post, "OAuth", "login_oauth", "Start an OAuth login", ResponseSet::Flow, false, false, routes.oauth.login_oauth, super::oauth::post_login_oauth;
    #[cfg(feature = "oauth")]
    SignupOAuth => post, "OAuth", "signup_oauth", "Start an OAuth signup", ResponseSet::Flow, false, false, routes.oauth.signup_oauth, super::oauth::post_signup_oauth;
    #[cfg(feature = "oauth")]
    UserOAuthLink => post, "OAuth", "user_oauth_link", "Link another OAuth account", ResponseSet::GuardedFlow, true, false, routes.oauth.user_oauth_link, super::oauth::post_user_oauth_link;
    #[cfg(feature = "oauth")]
    UserOAuthRefresh => post, "OAuth", "user_oauth_refresh", "Refresh an OAuth token", ResponseSet::OAuthRefresh, true, false, routes.oauth.user_oauth_refresh, super::oauth::post_user_oauth_refresh;
    #[cfg(feature = "oauth")]
    OAuthCallback => get, "OAuth", "oauth_callback", "Finish an OAuth flow", ResponseSet::Redirect, false, true, routes.oauth.callback, super::oauth::get_oauth;

    #[cfg(feature = "password")]
    LoginPassword => post, "Password", "login_password", "Log in with a password", ResponseSet::Flow, false, true, routes.password.login_password, super::password::post_login_password;
    #[cfg(feature = "password")]
    SignupPassword => post, "Password", "signup_password", "Sign up with a password", ResponseSet::Flow, false, true, routes.password.signup_password, super::password::post_signup_password;

    #[cfg(feature = "webauthn")]
    LoginWebauthnStart => post, "Passkeys", "login_webauthn_start", "Begin a passkey login", ResponseSet::WebauthnChallenge, false, false, routes.webauthn.login_webauthn_start, super::webauthn::post_login_webauthn_start;
    #[cfg(feature = "webauthn")]
    LoginWebauthnFinish => post, "Passkeys", "login_webauthn_finish", "Finish a passkey login", ResponseSet::WebauthnFinish, false, true, routes.webauthn.login_webauthn_finish, super::webauthn::post_login_webauthn_finish;
    #[cfg(feature = "webauthn")]
    UserWebauthnRegisterStart => post, "Passkeys", "user_webauthn_register_start", "Begin registering a passkey", ResponseSet::WebauthnChallenge, true, false, routes.webauthn.user_webauthn_register_start, super::webauthn::post_user_webauthn_register_start;
    #[cfg(feature = "webauthn")]
    UserWebauthnRegisterFinish => post, "Passkeys", "user_webauthn_register_finish", "Finish registering a passkey", ResponseSet::WebauthnFinish, true, false, routes.webauthn.user_webauthn_register_finish, super::webauthn::post_user_webauthn_register_finish;
    #[cfg(all(feature = "webauthn", feature = "user"))]
    UserWebauthnDelete => post, "Passkeys", "user_webauthn_delete", "Delete a passkey", ResponseSet::Flow, true, false, routes.webauthn.user_webauthn_delete, super::webauthn::post_user_webauthn_delete;

    #[cfg(all(feature = "mfa", feature = "email"))]
    LoginMfaOtp => post, "MFA", "login_mfa_otp", "Complete MFA with an emailed code", ResponseSet::Flow, true, true, routes.mfa.login_mfa_otp, super::mfa::post_login_mfa_otp;
    #[cfg(all(feature = "mfa", feature = "totp"))]
    LoginMfaTotp => post, "MFA", "login_mfa_totp", "Complete MFA with an authenticator code", ResponseSet::Flow, true, true, routes.mfa.login_mfa_totp, super::mfa::post_login_mfa_totp;
    #[cfg(all(feature = "mfa", feature = "sms"))]
    LoginMfaSms => post, "MFA", "login_mfa_sms", "Complete MFA with a texted code", ResponseSet::Flow, true, true, routes.mfa.login_mfa_sms, super::mfa::post_login_mfa_sms;
    #[cfg(feature = "mfa")]
    LoginMfaRecovery => post, "MFA", "login_mfa_recovery", "Complete MFA with a recovery code", ResponseSet::Flow, true, true, routes.mfa.login_mfa_recovery, super::mfa::post_login_mfa_recovery;
    #[cfg(all(feature = "mfa", feature = "webauthn"))]
    LoginMfaWebauthnStart => post, "MFA", "login_mfa_webauthn_start", "Begin MFA with a passkey", ResponseSet::WebauthnChallenge, true, false, routes.mfa.login_mfa_webauthn_start, super::mfa::post_login_mfa_webauthn_start;
    #[cfg(all(feature = "mfa", feature = "webauthn"))]
    LoginMfaWebauthnFinish => post, "MFA", "login_mfa_webauthn_finish", "Finish MFA with a passkey", ResponseSet::WebauthnFinish, true, true, routes.mfa.login_mfa_webauthn_finish, super::mfa::post_login_mfa_webauthn_finish;

    #[cfg(feature = "sms")]
    LoginSms => post, "SMS", "login_sms", "Log in with a texted code", ResponseSet::Flow, false, true, routes.sms.login_sms, super::sms::post_login_sms;
    #[cfg(feature = "sms")]
    SignupSms => post, "SMS", "signup_sms", "Sign up with a texted code", ResponseSet::Flow, false, true, routes.sms.signup_sms, super::sms::post_signup_sms;

    #[cfg(feature = "email")]
    LoginOtp => post, "Email", "login_otp", "Log in with an emailed code", ResponseSet::Flow, false, true, routes.email.login_otp, super::otp::post_login_otp;
    #[cfg(feature = "email")]
    SignupOtp => post, "Email", "signup_otp", "Sign up with an emailed code", ResponseSet::Flow, false, true, routes.email.signup_otp, super::otp::post_signup_otp;
    #[cfg(feature = "email")]
    LoginEmail => post, "Email", "login_email", "Send a login link", ResponseSet::Flow, false, false, routes.email.login_email, super::email::post_login_email;
    #[cfg(feature = "email")]
    LoginEmailCallback => get, "Email", "login_email_callback", "Finish a login link", ResponseSet::Redirect, false, true, routes.email.login_email, super::email::get_login_email;
    #[cfg(feature = "email")]
    SignupEmail => post, "Email", "signup_email", "Send a signup link", ResponseSet::Flow, false, false, routes.email.signup_email, super::email::post_signup_email;
    #[cfg(feature = "email")]
    SignupEmailCallback => get, "Email", "signup_email_callback", "Finish a signup link", ResponseSet::Redirect, false, true, routes.email.signup_email, super::email::get_signup_email;
    #[cfg(feature = "email")]
    UserEmailVerify => post, "Email", "user_email_verify", "Send an address-verification link", ResponseSet::GuardedFlow, true, false, routes.email.user_email_verify, super::email::post_user_email_verify;
    #[cfg(feature = "email")]
    UserEmailVerifyCallback => get, "Email", "user_email_verify_callback", "Finish an address-verification link", ResponseSet::Redirect, false, false, routes.email.user_email_verify, super::email::get_user_email_verify;
    #[cfg(all(feature = "email", feature = "password"))]
    PasswordReset => post, "Email", "password_reset", "Set a new password from a reset link", ResponseSet::GuardedFlow, false, false, routes.email.password_reset, super::email::post_password_reset;
    #[cfg(all(feature = "email", feature = "password"))]
    PasswordResetCallback => get, "Email", "password_reset_callback", "Finish a password-reset link", ResponseSet::Redirect, false, true, routes.email.password_reset_callback, super::email::get_password_reset_callback;
    #[cfg(all(feature = "email", feature = "password"))]
    PasswordSendReset => post, "Email", "password_send_reset", "Send a password-reset link", ResponseSet::Flow, false, false, routes.email.password_send_reset, super::email::post_password_send_reset;
}

#[cfg(feature = "openapi")]
impl Endpoint {
    /// Request body or query parameters for this endpoint, copied from the
    /// handler's extractors. This is the one per-endpoint match the macro
    /// cannot generate: it names types, not table columns.
    ///
    /// A `Query<T>` rejection on the callback GETs is still axum's plain
    /// text rather than the `ApiError` JSON the document promises; the body
    /// extractors (`FormOrJson`, `WebauthnJson`) both render `ApiError`.
    fn request(&self, d: &mut Describe, op: &mut Operation) {
        use super::*;
        match self {
            #[cfg(feature = "password")]
            Endpoint::LoginPassword | Endpoint::SignupPassword => {
                op.request_body = Some(d.body::<password::PasswordIdNextForm>())
            }
            #[cfg(feature = "email")]
            Endpoint::LoginOtp | Endpoint::SignupOtp => {
                op.request_body = Some(d.body::<otp::OtpForm>())
            }
            #[cfg(feature = "sms")]
            Endpoint::LoginSms | Endpoint::SignupSms => {
                op.request_body = Some(d.body::<sms::SmsForm>())
            }
            #[cfg(feature = "email")]
            Endpoint::LoginEmail | Endpoint::SignupEmail | Endpoint::UserEmailVerify => {
                op.request_body = Some(d.body::<email::EmailNextForm>())
            }
            #[cfg(all(feature = "email", feature = "password"))]
            Endpoint::PasswordSendReset => op.request_body = Some(d.body::<email::EmailNextForm>()),
            #[cfg(all(feature = "email", feature = "password"))]
            Endpoint::PasswordReset => op.request_body = Some(d.body::<email::NewPasswordForm>()),
            #[cfg(feature = "email")]
            Endpoint::LoginEmailCallback
            | Endpoint::SignupEmailCallback
            | Endpoint::UserEmailVerifyCallback => op.parameters = d.query::<email::CodeQuery>(),
            #[cfg(all(feature = "email", feature = "password"))]
            Endpoint::PasswordResetCallback => op.parameters = d.query::<email::CodeQuery>(),
            #[cfg(feature = "oauth")]
            Endpoint::LoginOAuth | Endpoint::SignupOAuth | Endpoint::UserOAuthLink => {
                op.request_body = Some(d.body::<oauth::ProviderNextForm>())
            }
            #[cfg(feature = "oauth")]
            Endpoint::UserOAuthRefresh => op.request_body = Some(d.body::<oauth::IdForm>()),
            #[cfg(feature = "oauth")]
            Endpoint::OAuthCallback => op.parameters = d.query::<oauth::CodeStateQuery>(),
            #[cfg(feature = "user")]
            Endpoint::UserSessionDelete => op.request_body = Some(d.body::<user::IdAccountForm>()),
            #[cfg(all(feature = "user", feature = "oauth"))]
            Endpoint::UserOAuthDelete => op.request_body = Some(d.body::<user::IdAccountForm>()),
            #[cfg(all(feature = "user", feature = "password"))]
            Endpoint::UserPasswordSet => {
                op.request_body = Some(d.body::<user::NewPasswordAccountForm>())
            }
            #[cfg(all(feature = "user", feature = "email"))]
            Endpoint::UserEmailAdd
            | Endpoint::UserEmailDelete
            | Endpoint::UserEmailEnableLogin
            | Endpoint::UserEmailDisableLogin => {
                op.request_body = Some(d.body::<user::EmailAccountForm>())
            }
            #[cfg(all(feature = "user", feature = "totp"))]
            Endpoint::UserTotpConfirm => op.request_body = Some(d.body::<user::TotpCodeForm>()),
            #[cfg(all(feature = "mfa", feature = "email"))]
            Endpoint::LoginMfaOtp => op.request_body = Some(d.body::<mfa::MfaCodeForm>()),
            #[cfg(all(feature = "mfa", feature = "sms"))]
            Endpoint::LoginMfaSms => op.request_body = Some(d.body::<mfa::MfaCodeForm>()),
            #[cfg(all(feature = "mfa", feature = "totp"))]
            Endpoint::LoginMfaTotp => op.request_body = Some(d.body::<mfa::MfaVerifyForm>()),
            #[cfg(feature = "mfa")]
            Endpoint::LoginMfaRecovery => op.request_body = Some(d.body::<mfa::MfaVerifyForm>()),
            #[cfg(all(feature = "mfa", feature = "webauthn"))]
            Endpoint::LoginMfaWebauthnFinish => {
                op.parameters = d.query::<mfa::TrustQuery>();
                op.request_body = Some(Describe::json_body(Describe::opaque_object(CREDENTIAL)));
            }
            #[cfg(feature = "webauthn")]
            Endpoint::LoginWebauthnFinish | Endpoint::UserWebauthnRegisterFinish => {
                op.request_body = Some(Describe::json_body(Describe::opaque_object(CREDENTIAL)))
            }
            #[cfg(feature = "webauthn")]
            Endpoint::UserWebauthnRegisterStart => {
                op.request_body = Some(d.body::<webauthn::RegisterStartBody>())
            }
            #[cfg(all(feature = "webauthn", feature = "user"))]
            Endpoint::UserWebauthnDelete => {
                op.request_body = Some(d.body::<webauthn::DeleteCredentialForm>())
            }
            #[cfg(feature = "pages")]
            Endpoint::LoginPage | Endpoint::SignupPage => {
                op.parameters = d.query::<pages::NextMessageErrorQuery>()
            }
            #[cfg(feature = "pages")]
            Endpoint::PausedPage => op.parameters = d.query::<pages::PausedQuery>(),
            #[cfg(all(feature = "pages", feature = "email"))]
            Endpoint::EmailSentPage | Endpoint::EmailExpiredPage => {
                op.parameters = d.query::<pages::EmailLinkQuery>()
            }
            #[cfg(all(feature = "pages", feature = "email", feature = "password"))]
            Endpoint::PasswordSendResetPage => {
                op.parameters = d.query::<pages::AddressMessageSentErrorQuery>()
            }
            #[cfg(all(feature = "pages", feature = "email", feature = "password"))]
            Endpoint::PasswordResetPage => {
                op.parameters = d.query::<pages::NextMessageErrorQuery>()
            }
            #[cfg(all(feature = "pages", feature = "user"))]
            Endpoint::UserPage => op.parameters = d.query::<pages::NextMessageErrorQuery>(),
            #[cfg(all(feature = "pages", feature = "mfa"))]
            Endpoint::LoginMfaPage => op.parameters = d.query::<pages::NextMessageErrorQuery>(),
            #[cfg(all(feature = "pages", feature = "sms"))]
            Endpoint::LoginSmsPage | Endpoint::SignupSmsPage => {
                op.parameters = d.query::<pages::OtpPageQuery>()
            }
            #[cfg(all(feature = "pages", feature = "email"))]
            Endpoint::LoginOtpPage | Endpoint::SignupOtpPage => {
                op.parameters = d.query::<pages::OtpPageQuery>()
            }
            // Everything else takes neither a body nor query parameters.
            _ => {}
        }
    }

    /// The whole operation: responses from the row's [`ResponseSet`],
    /// security from its `secured` column, request shape from [`Self::request`].
    pub(crate) fn describe(&self, d: &mut Describe) -> Operation {
        use crate::axum::response::{ApiError, FlowError, FlowResult};

        // The cookie layer emits `X-Auth-Token` exactly when the session
        // cookie changes, which is what the row's `establishes_session`
        // column records - including the MFA completion POSTs, which
        // require a pending session and still rotate it into a real one.
        let token = if self.establishes_session() {
            d.auth_token_header()
        } else {
            None
        };

        let mut responses = BTreeMap::new();
        for doc in self
            .response_set()
            .responses()
            .iter()
            .chain([&STORE_REFUSED, &INTERNAL_ERROR])
        {
            let mut response = match doc.body {
                Body::None => Describe::plain_response(doc.description),
                Body::FlowResult => d.json_response::<FlowResult>(doc.description),
                Body::FlowError => d.json_response::<FlowError>(doc.description),
                Body::ApiError => d.json_response::<ApiError>(doc.description),
                Body::Html => Describe::html_response(doc.description),
                Body::Challenge => {
                    Describe::schema_response(Describe::opaque_object(CHALLENGE), doc.description)
                }
            };
            if doc.token
                && let Some((name, header)) = token.clone()
            {
                response.headers.insert(name, header);
            }
            responses.insert(doc.status.label(), response);
        }

        let mut op = Operation {
            operation_id: self.name().into(),
            tags: vec![self.tag().into()],
            summary: self.summary().into(),
            parameters: Vec::new(),
            request_body: None,
            responses,
            security: if self.secured() {
                d.security()
            } else {
                Vec::new()
            },
        };
        self.request(d, &mut op);
        op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every mounted (method, path) pair is unique under the default routes,
    /// and names are unique so they can serve as operation ids.
    #[test]
    fn endpoints_are_unique() {
        let routes: Routes<String> = Routes::default().into();
        let mut seen = HashSet::new();
        let mut names = HashSet::new();
        for endpoint in Endpoint::all() {
            let key = (endpoint.method(), endpoint.path(&routes).to_string());
            assert!(seen.insert(key.clone()), "duplicate route {key:?}");
            assert!(
                names.insert(endpoint.name()),
                "duplicate name {}",
                endpoint.name()
            );
        }
        assert!(!seen.is_empty());
    }
}

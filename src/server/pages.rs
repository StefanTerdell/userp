#[cfg(feature = "server-email")]
use crate::models::{email::UserEmail, oauth::OAuthToken, LoginSession, User, UserpCookies};
#[cfg(feature = "oauth-action-routes")]
use crate::server::oauth::provider::OAuthProvider;
use crate::{
    models::LoginMethod,
    server::{core::CoreUserp, store::UserpStore},
};
use askama::Template;
#[cfg(feature = "axum-router-pages")]
use askama_axum::IntoResponse;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(feature = "server-account")]
pub struct TemplateLoginSession {
    pub id: Uuid,
    pub method: LoginMethod,
}

#[cfg(feature = "server-account")]
impl<T: LoginSession> From<&T> for TemplateLoginSession {
    fn from(value: &T) -> Self {
        TemplateLoginSession {
            id: value.get_id(),
            method: value.get_method(),
        }
    }
}

pub struct TemplateUserEmail<'a> {
    address: &'a str,
    verified: bool,
    allow_link_login: bool,
}

#[cfg(feature = "server-email")]
impl<'a, T: UserEmail> From<&'a T> for TemplateUserEmail<'a> {
    fn from(value: &'a T) -> Self {
        Self {
            address: value.get_address(),
            verified: value.get_verified(),
            allow_link_login: value.get_allow_link_login(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TemplateOAuthToken<'a> {
    pub id: Uuid,
    pub provider_name: &'a str,
}

#[cfg(feature = "oauth-action-routes")]
impl<'a, T: OAuthToken> From<&'a T> for TemplateOAuthToken<'a> {
    fn from(value: &'a T) -> Self {
        Self {
            id: value.get_id(),
            provider_name: value.get_provider_name(),
        }
    }
}

pub struct TemplateOAuthProvider<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
}

#[cfg(feature = "oauth-action-routes")]
impl<'a> From<&'a Arc<dyn OAuthProvider>> for TemplateOAuthProvider<'a> {
    fn from(value: &'a Arc<dyn OAuthProvider>) -> Self {
        Self {
            name: value.name(),
            display_name: value.display_name(),
        }
    }
}

#[cfg(all(feature = "server-password", feature = "server-email"))]
#[derive(Template)]
#[template(path = "reset-password.html")]
pub struct ResetPasswordTemplate<'a> {
    pub reset_password_action_route: &'a str,
}

#[cfg(all(feature = "server-password", feature = "server-email"))]
#[derive(Template)]
#[template(path = "send-reset-password.html")]
pub struct SendResetPasswordTemplate<'a> {
    pub sent: bool,
    pub address: Option<&'a str>,
    pub error: Option<&'a str>,
    pub message: Option<&'a str>,
    pub send_reset_password_action_route: &'a str,
}

#[cfg(feature = "server-account")]
pub struct UserTemplatePasswordInfo<'a> {
    pub has_password: bool,
    pub delete_action_route: &'a str,
    pub set_action_route: &'a str,
}

#[cfg(feature = "server-account")]
pub struct UserTemplateEmailInfo<'a> {
    pub emails: Vec<TemplateUserEmail<'a>>,
    pub delete_action_route: &'a str,
    pub add_action_route: &'a str,
    pub verify_action_route: &'a str,
    pub enable_login_action_route: &'a str,
    pub disable_login_action_route: &'a str,
}

#[cfg(feature = "server-account")]
pub struct UserTemplateOAuthInfo<'a> {
    pub tokens: Vec<TemplateOAuthToken<'a>>,
    pub providers: Vec<TemplateOAuthProvider<'a>>,
    pub delete_action_route: &'a str,
    pub refresh_action_route: &'a str,
    pub link_action_route: &'a str,
    pub user_page_route: &'a str,
}

#[cfg(feature = "server-account")]
#[derive(Template)]
#[template(path = "user.html")]
pub struct UserTemplate<'a> {
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub session_id: Uuid,
    pub sessions: Vec<TemplateLoginSession>,
    pub home_page_route: &'a str,
    pub login_page_route: &'a str,
    pub session_delete_action_route: &'a str,
    pub user_delete_action_route: &'a str,
    pub verify_session_action_route: &'a str,
    pub password: Option<UserTemplatePasswordInfo<'a>>,
    pub email: Option<UserTemplateEmailInfo<'a>>,
    pub oauth: Option<UserTemplateOAuthInfo<'a>>,
}

#[cfg(feature = "server-account")]
impl UserTemplate<'_> {
    #[allow(clippy::too_many_arguments)]
    fn with<'a, S: UserpStore, C: UserpCookies>(
        auth: &'a CoreUserp<S, C>,
        user: &'a S::User,
        session: &'a S::LoginSession,
        sessions: &'a [S::LoginSession],
        message: Option<&'a str>,
        error: Option<&'a str>,
        #[cfg(feature = "server-email")] emails: &'a [S::UserEmail],
        #[cfg(feature = "oauth-action-routes")] oauth_tokens: &'a [S::OAuthToken],
    ) -> UserTemplate<'a> {
        UserTemplate {
            message,
            error,
            session_id: session.get_id(),
            sessions: sessions.iter().map(|s| s.into()).collect(),
            home_page_route: &auth.routes.pages.home,
            login_page_route: &auth.routes.pages.login,
            session_delete_action_route: &auth.routes.account.user_session_delete,
            user_delete_action_route: &auth.routes.account.user_delete,
            verify_session_action_route: &auth.routes.user_verify_session,
            #[cfg(feature = "server-password")]
            password: Some(UserTemplatePasswordInfo {
                has_password: user.get_password_hash().is_some(),
                delete_action_route: &auth.routes.account.user_password_delete,
                set_action_route: &auth.routes.account.user_password_set,
            }),
            #[cfg(not(feature = "server-password"))]
            password: None,
            #[cfg(feature = "server-email")]
            email: Some(UserTemplateEmailInfo {
                emails: emails.iter().map(|e| e.into()).collect(),
                delete_action_route: &auth.routes.account.user_email_delete,
                add_action_route: &auth.routes.account.user_email_add,
                verify_action_route: &auth.routes.email.user_email_verify,
                enable_login_action_route: &auth.routes.account.user_email_enable_login,
                disable_login_action_route: &auth.routes.account.user_email_disable_login,
            }),
            #[cfg(not(feature = "server-email"))]
            email: None,
            #[cfg(feature = "oauth-action-routes")]
            oauth: {
                Some(UserTemplateOAuthInfo {
                    tokens: oauth_tokens.iter().map(|t| t.into()).collect(),
                    providers: auth
                        .oauth_link_providers()
                        .into_iter()
                        .filter_map(|p| {
                            if oauth_tokens
                                .iter()
                                .any(|t| t.get_provider_name() == p.name())
                            {
                                None
                            } else {
                                Some(p.into())
                            }
                        })
                        .collect(),
                    delete_action_route: &auth.routes.account.user_oauth_delete,
                    refresh_action_route: &auth.routes.oauth.actions.user_oauth_refresh,
                    link_action_route: &auth.routes.oauth.actions.user_oauth_link,
                    user_page_route: &auth.routes.pages.user,
                })
            },
            #[cfg(not(feature = "oauth-action-routes"))]
            oauth: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "axum-router-pages")]
    pub fn render_with<S: UserpStore, C: UserpCookies>(
        auth: &CoreUserp<S, C>,
        user: &S::User,
        session: &S::LoginSession,
        sessions: &[S::LoginSession],
        message: Option<&str>,
        error: Option<&str>,
        #[cfg(feature = "server-email")] emails: &[S::UserEmail],
        #[cfg(feature = "oauth-action-routes")] oauth_tokens: &[S::OAuthToken],
    ) -> Result<String, askama::Error> {
        Self::with(
            auth,
            user,
            session,
            sessions,
            message,
            error,
            #[cfg(feature = "server-email")]
            emails,
            #[cfg(feature = "oauth-action-routes")]
            oauth_tokens,
        )
        .render()
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "axum-router-pages")]
    pub fn into_response_with<S: UserpStore, C: UserpCookies>(
        auth: &CoreUserp<S, C>,
        user: &S::User,
        session: &S::LoginSession,
        sessions: &[S::LoginSession],
        message: Option<&str>,
        error: Option<&str>,
        #[cfg(feature = "server-email")] emails: &[S::UserEmail],
        #[cfg(feature = "oauth-action-routes")] oauth_tokens: &[S::OAuthToken],
    ) -> impl IntoResponse {
        Self::with(
            auth,
            user,
            session,
            sessions,
            message,
            error,
            #[cfg(feature = "server-email")]
            emails,
            #[cfg(feature = "oauth-action-routes")]
            oauth_tokens,
        )
        .into_response()
    }
}

pub struct TemplateOAuthInfo<'a> {
    pub providers: Vec<TemplateOAuthProvider<'a>>,
    pub action_route: &'a str,
}

pub struct TemplateEmailInfo<'a> {
    pub action_route: &'a str,
}

pub struct TemplatePasswordInfo<'a> {
    pub action_route: &'a str,
    pub reset_route: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub next: Option<&'a str>,
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub password: Option<TemplatePasswordInfo<'a>>,
    pub email: Option<TemplateEmailInfo<'a>>,
    pub oauth: Option<TemplateOAuthInfo<'a>>,
    pub signup_route: &'a str,
}

impl LoginTemplate<'_> {
    fn with<'a, S: UserpStore, C: UserpCookies>(
        auth: &'a CoreUserp<S, C>,
        next: Option<&'a str>,
        message: Option<&'a str>,
        error: Option<&'a str>,
    ) -> LoginTemplate<'a> {
        #[cfg(feature = "oauth-action-routes")]
        let oauth_login_providers = auth.oauth_login_providers();

        LoginTemplate {
            next,
            message,
            error,
            #[cfg(feature = "server-password")]
            password: Some(TemplatePasswordInfo {
                action_route: &auth.routes.password.login_password,
                #[cfg(feature = "server-email")]
                reset_route: Some(&auth.routes.pages.password_send_reset),
                #[cfg(not(feature = "server-email"))]
                reset_route: None,
            }),
            #[cfg(not(feature = "server-password"))]
            password: None,
            #[cfg(feature = "server-email")]
            email: Some(TemplateEmailInfo {
                action_route: &auth.routes.email.login_email,
            }),
            #[cfg(not(feature = "server-email"))]
            email: None,
            #[cfg(feature = "oauth-action-routes")]
            oauth: ({
                if oauth_login_providers.is_empty() {
                    None
                } else {
                    Some(TemplateOAuthInfo {
                        providers: oauth_login_providers
                            .into_iter()
                            .map(|p| p.into())
                            .collect(),
                        action_route: &auth.routes.oauth.actions.login_oauth,
                    })
                }
            }),
            #[cfg(not(feature = "oauth-action-routes"))]
            oauth: None,
            signup_route: &auth.routes.pages.signup,
        }
    }

    pub fn render_with<S: UserpStore, C: UserpCookies>(
        auth: &CoreUserp<S, C>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> Result<String, askama::Error> {
        Self::with(auth, next, message, error).render()
    }

    #[cfg(feature = "axum-router-pages")]
    pub fn into_response_with<S: UserpStore, C: UserpCookies>(
        auth: &CoreUserp<S, C>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> impl IntoResponse {
        Self::with(auth, next, message, error).into_response()
    }
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupTemplate<'a> {
    pub next: Option<&'a str>,
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub password: Option<TemplatePasswordInfo<'a>>,
    pub email: Option<TemplateEmailInfo<'a>>,
    pub oauth: Option<TemplateOAuthInfo<'a>>,
    pub login_route: &'a str,
}

impl SignupTemplate<'_> {
    fn with<'a, S: UserpStore, C: UserpCookies>(
        auth: &'a CoreUserp<S, C>,
        next: Option<&'a str>,
        message: Option<&'a str>,
        error: Option<&'a str>,
    ) -> SignupTemplate<'a> {
        #[cfg(feature = "oauth-action-routes")]
        let oauth_signup_providers = auth.oauth_signup_providers();

        SignupTemplate {
            next,
            message,
            error,
            #[cfg(feature = "server-password")]
            password: Some(TemplatePasswordInfo {
                action_route: &auth.routes.password.signup_password,
                #[cfg(feature = "server-email")]
                reset_route: Some(&auth.routes.pages.password_send_reset),
                #[cfg(not(feature = "server-email"))]
                reset_route: None,
            }),
            #[cfg(not(feature = "server-password"))]
            password: None,
            #[cfg(feature = "server-email")]
            email: Some(TemplateEmailInfo {
                action_route: &auth.routes.email.signup_email,
            }),
            #[cfg(not(feature = "server-email"))]
            email: None,
            #[cfg(feature = "oauth-action-routes")]
            oauth: ({
                if oauth_signup_providers.is_empty() {
                    None
                } else {
                    Some(TemplateOAuthInfo {
                        providers: oauth_signup_providers
                            .into_iter()
                            .map(|p| p.into())
                            .collect(),
                        action_route: &auth.routes.oauth.actions.signup_oauth,
                    })
                }
            }),
            #[cfg(not(feature = "oauth-action-routes"))]
            oauth: None,
            login_route: &auth.routes.pages.login,
        }
    }

    pub fn render_with<S: UserpStore, C: UserpCookies>(
        auth: &CoreUserp<S, C>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> Result<String, askama::Error> {
        Self::with(auth, next, message, error).render()
    }

    #[cfg(feature = "axum-router-pages")]
    pub fn response_from<S: UserpStore, C: UserpCookies>(
        auth: &CoreUserp<S, C>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> impl IntoResponse {
        Self::with(auth, next, message, error).into_response()
    }
}

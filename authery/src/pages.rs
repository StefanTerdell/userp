#![cfg_attr(not(feature = "default"), allow(unused))]

use askama::Template;
use std::sync::Arc;
use crate::models::LoginMethod;
#[cfg(feature = "email")]
use crate::models::email::UserEmail;
use crate::models::{LoginSession, User, AutheryCookies};
use crate::{core::CoreAuthery, store::AutheryStore};
#[cfg(feature = "oauth")]
use crate::{models::oauth::OAuthToken, oauth::provider::OAuthProvider};


#[cfg(feature = "user")]
pub struct TemplateLoginSession {
    pub id: String,
    pub method: LoginMethod,
}

#[cfg(feature = "user")]
impl<T: LoginSession> From<&T> for TemplateLoginSession {
    fn from(value: &T) -> Self {
        TemplateLoginSession {
            id: value.get_id().to_string(),
            method: value.get_method(),
        }
    }
}

pub struct TemplateUserEmail<'a> {
    address: &'a str,
    verified: bool,
    allow_link_login: bool,
}

#[cfg(feature = "email")]
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
    pub id: String,
    pub provider_name: &'a str,
}

#[cfg(feature = "oauth")]
impl<'a, T: OAuthToken> From<&'a T> for TemplateOAuthToken<'a> {
    fn from(value: &'a T) -> Self {
        Self {
            id: value.get_id().to_string(),
            provider_name: value.get_provider_name(),
        }
    }
}

pub struct TemplateOAuthProvider<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
}

#[cfg(feature = "oauth")]
impl<'a> From<&'a Arc<dyn OAuthProvider>> for TemplateOAuthProvider<'a> {
    fn from(value: &'a Arc<dyn OAuthProvider>) -> Self {
        Self {
            name: value.name(),
            display_name: value.display_name(),
        }
    }
}

#[cfg(all(feature = "password", feature = "email"))]
#[derive(Template)]
#[template(path = "reset-password.html")]
pub struct ResetPasswordTemplate<'a> {
    pub reset_password_action_route: &'a str,
}

#[cfg(all(feature = "password", feature = "email"))]
#[derive(Template)]
#[template(path = "send-reset-password.html")]
pub struct SendResetPasswordTemplate<'a> {
    pub sent: bool,
    pub address: Option<&'a str>,
    pub error: Option<&'a str>,
    pub message: Option<&'a str>,
    pub send_reset_password_action_route: &'a str,
}

#[cfg(feature = "user")]
pub struct UserTemplatePasswordInfo<'a> {
    pub has_password: bool,
    pub delete_action_route: &'a str,
    pub set_action_route: &'a str,
}

#[cfg(feature = "user")]
pub struct UserTemplateEmailInfo<'a> {
    pub emails: Vec<TemplateUserEmail<'a>>,
    pub delete_action_route: &'a str,
    pub add_action_route: &'a str,
    pub verify_action_route: &'a str,
    pub enable_login_action_route: &'a str,
    pub disable_login_action_route: &'a str,
}

#[cfg(feature = "user")]
pub struct UserTemplateOAuthInfo<'a> {
    pub tokens: Vec<TemplateOAuthToken<'a>>,
    pub providers: Vec<TemplateOAuthProvider<'a>>,
    pub delete_action_route: &'a str,
    pub refresh_action_route: &'a str,
    pub link_action_route: &'a str,
    pub user_page_route: &'a str,
}

#[cfg(feature = "user")]
#[derive(Template)]
#[template(path = "user.html")]
pub struct UserTemplate<'a> {
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub session_id: String,
    pub sessions: Vec<TemplateLoginSession>,
    pub home_page_route: &'a str,
    pub login_page_route: &'a str,
    pub session_delete_action_route: &'a str,
    pub user_delete_action_route: &'a str,
    pub verify_session_action_route: &'a str,
    pub password: Option<UserTemplatePasswordInfo<'a>>,
    pub email: Option<UserTemplateEmailInfo<'a>>,
    pub oauth: Option<UserTemplateOAuthInfo<'a>>,
    pub webauthn: Option<UserTemplateWebauthnInfo<'a>>,
}

#[cfg(feature = "user")]
impl UserTemplate<'_> {
    /// Assemble the account page's view-model from the auth context. See
    /// [`LoginTemplate::with`].
    #[allow(clippy::too_many_arguments)]
    pub fn with<'a, S: AutheryStore, C: AutheryCookies>(
        auth: &'a CoreAuthery<S, C>,
        user: &'a S::User,
        session: &'a S::LoginSession,
        sessions: &'a [S::LoginSession],
        message: Option<&'a str>,
        error: Option<&'a str>,
        #[cfg(feature = "email")] emails: &'a [S::UserEmail],
        #[cfg(feature = "oauth")] oauth_tokens: &'a [S::OAuthToken],
        #[cfg(feature = "webauthn")] passkey_credential_ids: Vec<String>,
    ) -> UserTemplate<'a> {
        UserTemplate {
            message,
            error,
            session_id: session.get_id().to_string(),
            sessions: sessions.iter().map(|s| s.into()).collect(),
            home_page_route: &auth.routes.pages.home,
            login_page_route: &auth.routes.pages.login,
            session_delete_action_route: &auth.routes.user.user_session_delete,
            user_delete_action_route: &auth.routes.user.user_delete,
            verify_session_action_route: &auth.routes.user_verify_session,
            #[cfg(feature = "password")]
            password: Some(UserTemplatePasswordInfo {
                has_password: user.get_password_hash().is_some(),
                delete_action_route: &auth.routes.user.user_password_delete,
                set_action_route: &auth.routes.user.user_password_set,
            }),
            #[cfg(not(feature = "password"))]
            password: None,
            #[cfg(feature = "email")]
            email: Some(UserTemplateEmailInfo {
                emails: emails.iter().map(|e| e.into()).collect(),
                delete_action_route: &auth.routes.user.user_email_delete,
                add_action_route: &auth.routes.user.user_email_add,
                verify_action_route: &auth.routes.email.user_email_verify,
                enable_login_action_route: &auth.routes.user.user_email_enable_login,
                disable_login_action_route: &auth.routes.user.user_email_disable_login,
            }),
            #[cfg(not(feature = "email"))]
            email: None,
            #[cfg(feature = "oauth")]
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
                    delete_action_route: &auth.routes.user.user_oauth_delete,
                    refresh_action_route: &auth.routes.oauth.actions.user_oauth_refresh,
                    link_action_route: &auth.routes.oauth.actions.user_oauth_link,
                    user_page_route: &auth.routes.pages.user,
                })
            },
            #[cfg(not(feature = "oauth"))]
            oauth: None,
            #[cfg(feature = "webauthn")]
            webauthn: Some(UserTemplateWebauthnInfo {
                credential_ids: passkey_credential_ids,
                register_start_route: &auth.routes.webauthn.user_webauthn_register_start,
                register_finish_route: &auth.routes.webauthn.user_webauthn_register_finish,
                delete_action_route: &auth.routes.webauthn.user_webauthn_delete,
            }),
            #[cfg(not(feature = "webauthn"))]
            webauthn: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "axum")]
    pub fn render_with<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        user: &S::User,
        session: &S::LoginSession,
        sessions: &[S::LoginSession],
        message: Option<&str>,
        error: Option<&str>,
        #[cfg(feature = "email")] emails: &[S::UserEmail],
        #[cfg(feature = "oauth")] oauth_tokens: &[S::OAuthToken],
        #[cfg(feature = "webauthn")] passkey_credential_ids: Vec<String>,
    ) -> Result<String, askama::Error> {
        Self::with(
            auth,
            user,
            session,
            sessions,
            message,
            error,
            #[cfg(feature = "email")]
            emails,
            #[cfg(feature = "oauth")]
            oauth_tokens,
            #[cfg(feature = "webauthn")]
            passkey_credential_ids,
        )
        .render()
    }
}

pub struct TemplateOAuthInfo<'a> {
    pub providers: Vec<TemplateOAuthProvider<'a>>,
    pub action_route: &'a str,
}

pub struct TemplateEmailInfo<'a> {
    pub action_route: &'a str,
}

pub struct TemplateOtpInfo<'a> {
    pub action_route: &'a str,
}

pub struct TemplateWebauthnInfo<'a> {
    pub start_route: &'a str,
    pub finish_route: &'a str,
}

/// Rendered on org-scoped login pages (`/login/{slug}`): the org's own SSO
/// providers, posted to the oauth action route with the org slug attached.
pub struct TemplateOrgLoginInfo<'a> {
    pub slug: &'a str,
    pub name: &'a str,
    pub providers: Vec<TemplateOAuthProvider<'a>>,
    pub action_route: &'a str,
}

#[cfg(feature = "user")]
pub struct UserTemplateWebauthnInfo<'a> {
    /// Hex-encoded credential ids of the user's registered passkeys.
    pub credential_ids: Vec<String>,
    pub register_start_route: &'a str,
    pub register_finish_route: &'a str,
    pub delete_action_route: &'a str,
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
    pub otp: Option<TemplateOtpInfo<'a>>,
    pub webauthn: Option<TemplateWebauthnInfo<'a>>,
    pub oauth: Option<TemplateOAuthInfo<'a>>,
    pub org: Option<TemplateOrgLoginInfo<'a>>,
    pub signup_route: &'a str,
}

impl LoginTemplate<'_> {
    /// Assemble the login page's view-model from the auth context. Public so
    /// apps writing their own handlers - or a custom [`Pages`] renderer - can
    /// reuse the exact data the built-in template sees.
    pub fn with<'a, S: AutheryStore, C: AutheryCookies>(
        auth: &'a CoreAuthery<S, C>,
        next: Option<&'a str>,
        message: Option<&'a str>,
        error: Option<&'a str>,
    ) -> LoginTemplate<'a> {
        #[cfg(feature = "oauth")]
        let oauth_login_providers = auth.oauth_login_providers();

        LoginTemplate {
            next,
            message,
            error,
            #[cfg(feature = "password")]
            password: Some(TemplatePasswordInfo {
                action_route: &auth.routes.password.login_password,
                #[cfg(feature = "email")]
                reset_route: Some(&auth.routes.pages.password_send_reset),
                #[cfg(not(feature = "email"))]
                reset_route: None,
            }),
            #[cfg(not(feature = "password"))]
            password: None,
            #[cfg(feature = "email")]
            email: Some(TemplateEmailInfo {
                action_route: &auth.routes.email.login_email,
            }),
            #[cfg(not(feature = "email"))]
            email: None,
            #[cfg(feature = "otp")]
            otp: Some(TemplateOtpInfo {
                action_route: &auth.routes.email.login_otp,
            }),
            #[cfg(not(feature = "otp"))]
            otp: None,
            #[cfg(feature = "webauthn")]
            webauthn: Some(TemplateWebauthnInfo {
                start_route: &auth.routes.webauthn.login_webauthn_start,
                finish_route: &auth.routes.webauthn.login_webauthn_finish,
            }),
            #[cfg(not(feature = "webauthn"))]
            webauthn: None,
            #[cfg(feature = "oauth")]
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
            #[cfg(not(feature = "oauth"))]
            oauth: None,
            org: None,
            signup_route: &auth.routes.pages.signup,
        }
    }

    /// Assemble the org-scoped login page's view-model: like
    /// [`LoginTemplate::with`], but with the org's own providers added and the
    /// password/email sections hidden when the org's login rules disallow
    /// them.
    #[cfg(all(feature = "organizations", feature = "oauth"))]
    #[allow(clippy::too_many_arguments)]
    pub fn with_org<'a, S: AutheryStore, C: AutheryCookies>(
        auth: &'a CoreAuthery<S, C>,
        org: &'a S::Organization,
        org_providers: &'a [S::OrgOidcProvider],
        next: Option<&'a str>,
        message: Option<&'a str>,
        error: Option<&'a str>,
    ) -> LoginTemplate<'a> {
        use crate::models::org::{OrgOidcProvider, Organization};

        let rules = org.get_login_rules();
        let mut template = Self::with(auth, next, message, error);

        if !rules.allow_password {
            template.password = None;
        }
        if !rules.allow_email {
            template.email = None;
            template.otp = None;
        }

        template.org = Some(TemplateOrgLoginInfo {
            slug: org.get_slug(),
            name: org.get_name(),
            providers: org_providers
                .iter()
                .filter(|p| p.get_allow_login())
                .map(|p| TemplateOAuthProvider {
                    name: p.get_name(),
                    display_name: p.get_display_name(),
                })
                .collect(),
            action_route: &auth.routes.oauth.actions.login_oauth,
        });

        template
    }

    pub fn render_with<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> Result<String, askama::Error> {
        Self::with(auth, next, message, error).render()
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
    pub otp: Option<TemplateOtpInfo<'a>>,
    pub oauth: Option<TemplateOAuthInfo<'a>>,
    pub login_route: &'a str,
}

impl SignupTemplate<'_> {
    /// Assemble the signup page's view-model from the auth context. See
    /// [`LoginTemplate::with`].
    pub fn with<'a, S: AutheryStore, C: AutheryCookies>(
        auth: &'a CoreAuthery<S, C>,
        next: Option<&'a str>,
        message: Option<&'a str>,
        error: Option<&'a str>,
    ) -> SignupTemplate<'a> {
        #[cfg(feature = "oauth")]
        let oauth_signup_providers = auth.oauth_signup_providers();

        SignupTemplate {
            next,
            message,
            error,
            #[cfg(feature = "password")]
            password: Some(TemplatePasswordInfo {
                action_route: &auth.routes.password.signup_password,
                #[cfg(feature = "email")]
                reset_route: Some(&auth.routes.pages.password_send_reset),
                #[cfg(not(feature = "email"))]
                reset_route: None,
            }),
            #[cfg(not(feature = "password"))]
            password: None,
            #[cfg(feature = "email")]
            email: Some(TemplateEmailInfo {
                action_route: &auth.routes.email.signup_email,
            }),
            #[cfg(not(feature = "email"))]
            email: None,
            #[cfg(feature = "otp")]
            otp: Some(TemplateOtpInfo {
                action_route: &auth.routes.email.signup_otp,
            }),
            #[cfg(not(feature = "otp"))]
            otp: None,
            #[cfg(feature = "oauth")]
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
            #[cfg(not(feature = "oauth"))]
            oauth: None,
            login_route: &auth.routes.pages.login,
        }
    }

    pub fn render_with<S: AutheryStore, C: AutheryCookies>(
        auth: &CoreAuthery<S, C>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> Result<String, askama::Error> {
        Self::with(auth, next, message, error).render()
    }
}

#[cfg(feature = "mfa")]
pub struct MfaOtpTemplateInfo<'a> {
    pub action_route: &'a str,
    /// A masked rendering of the address the code goes to, e.g. `s***@x.com`.
    pub address_hint: String,
}

#[cfg(feature = "mfa")]
pub struct MfaWebauthnTemplateInfo<'a> {
    pub start_route: &'a str,
    pub finish_route: &'a str,
}

/// The second-factor picker shown after a first factor succeeded but the MFA
/// policy demands more. Offers only factors the pending user actually has.
#[cfg(feature = "mfa")]
#[derive(Template)]
#[template(path = "mfa.html")]
pub struct MfaTemplate<'a> {
    pub next: Option<&'a str>,
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub otp: Option<MfaOtpTemplateInfo<'a>>,
    pub webauthn: Option<MfaWebauthnTemplateInfo<'a>>,
}

/// The one-time-code entry page: the user has been sent a code and types it
/// here. `action_route` is the OTP route the form posts back to (login or
/// signup), with the address carried in a hidden field.
#[derive(Template)]
#[template(path = "otp.html")]
pub struct OtpTemplate<'a> {
    pub address: &'a str,
    pub action_route: &'a str,
    pub next: Option<&'a str>,
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
}

#[cfg(feature = "organizations")]
pub struct OrgsTemplateItem {
    pub slug: String,
    pub name: String,
    /// Effective roles, comma-joined for display.
    pub roles: String,
    pub page_route: String,
}

/// The organizations overview: the user's memberships plus a create form.
#[cfg(feature = "organizations")]
#[derive(Template)]
#[template(path = "orgs.html")]
pub struct OrgsTemplate<'a> {
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub orgs: Vec<OrgsTemplateItem>,
    pub create_action_route: &'a str,
    pub home_route: &'a str,
}

#[cfg(feature = "organizations")]
pub struct OrgTemplateMember {
    pub user_id: String,
    /// Comma-joined for display.
    pub roles: String,
}

#[cfg(feature = "organizations")]
pub struct OrgTemplateChild {
    pub slug: String,
    pub name: String,
    pub page_route: String,
}

#[cfg(feature = "organizations")]
pub struct OrgTemplateProvider {
    pub name: String,
    pub display_name: String,
    pub issuer: String,
}

/// The management page for one organization. Owner-only sections (settings,
/// invites, providers) render when `is_owner`.
#[cfg(feature = "organizations")]
#[derive(Template)]
#[template(path = "org.html")]
pub struct OrgTemplate<'a> {
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub slug: &'a str,
    pub name: &'a str,
    pub is_owner: bool,
    /// The viewer's effective roles, comma-joined.
    pub roles: String,
    pub rules: crate::models::org::OrgLoginRules,
    /// `parent_role=role_here` lines for the settings textarea.
    pub role_inheritance: String,
    pub members: Vec<OrgTemplateMember>,
    pub children: Vec<OrgTemplateChild>,
    /// Org SSO providers; empty when the oauth feature is off.
    pub providers: Vec<OrgTemplateProvider>,
    /// The org-scoped login page path.
    pub login_route: String,
    pub orgs_route: &'a str,
    pub update_action_route: String,
    pub delete_action_route: String,
    pub member_upsert_action_route: String,
    pub member_remove_action_route: String,
    pub sub_create_action_route: String,
    pub invite_create_action_route: String,
    pub provider_upsert_action_route: String,
    pub provider_delete_action_route: String,
}

/// Renders the built-in pages to HTML. Implement this and register it with
/// [`crate::config::AutheryConfig::with_pages`] to replace the bundled Askama
/// templates with your own markup while keeping the built-in router and flows.
///
/// Each method receives the same view-model the bundled template sees - the
/// public `*Template` structs, whose fields carry every route and flag the page
/// needs. Return the rendered HTML as a string.
pub trait Pages: std::fmt::Debug + Send + Sync {
    fn render_login(&self, view: &LoginTemplate<'_>) -> String;
    fn render_signup(&self, view: &SignupTemplate<'_>) -> String;
    #[cfg(feature = "otp")]
    fn render_otp(&self, view: &OtpTemplate<'_>) -> String;
    #[cfg(feature = "mfa")]
    fn render_mfa(&self, view: &MfaTemplate<'_>) -> String;
    #[cfg(feature = "organizations")]
    fn render_orgs(&self, view: &OrgsTemplate<'_>) -> String;
    #[cfg(feature = "organizations")]
    fn render_org(&self, view: &OrgTemplate<'_>) -> String;
    #[cfg(feature = "user")]
    fn render_user(&self, view: &UserTemplate<'_>) -> String;
    #[cfg(all(feature = "password", feature = "email"))]
    fn render_send_reset_password(&self, view: &SendResetPasswordTemplate<'_>) -> String;
    #[cfg(all(feature = "password", feature = "email"))]
    fn render_reset_password(&self, view: &ResetPasswordTemplate<'_>) -> String;
}

/// The default [`Pages`] renderer, backed by the bundled Askama templates.
#[derive(Debug, Clone, Default)]
pub struct AskamaPages;

/// Render a template to a string, falling back to the error text so a broken
/// template surfaces the problem rather than an empty page.
fn render_or_err<T: Template>(template: &T) -> String {
    template.render().unwrap_or_else(|err| err.to_string())
}

impl Pages for AskamaPages {
    fn render_login(&self, view: &LoginTemplate<'_>) -> String {
        render_or_err(view)
    }

    fn render_signup(&self, view: &SignupTemplate<'_>) -> String {
        render_or_err(view)
    }

    #[cfg(feature = "otp")]
    fn render_otp(&self, view: &OtpTemplate<'_>) -> String {
        render_or_err(view)
    }

    #[cfg(feature = "mfa")]
    fn render_mfa(&self, view: &MfaTemplate<'_>) -> String {
        render_or_err(view)
    }

    #[cfg(feature = "organizations")]
    fn render_orgs(&self, view: &OrgsTemplate<'_>) -> String {
        render_or_err(view)
    }

    #[cfg(feature = "organizations")]
    fn render_org(&self, view: &OrgTemplate<'_>) -> String {
        render_or_err(view)
    }

    #[cfg(feature = "user")]
    fn render_user(&self, view: &UserTemplate<'_>) -> String {
        render_or_err(view)
    }

    #[cfg(all(feature = "password", feature = "email"))]
    fn render_send_reset_password(&self, view: &SendResetPasswordTemplate<'_>) -> String {
        render_or_err(view)
    }

    #[cfg(all(feature = "password", feature = "email"))]
    fn render_reset_password(&self, view: &ResetPasswordTemplate<'_>) -> String {
        render_or_err(view)
    }
}

use axum::extract::Query;
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;
use crate::pages::{LoginTemplate, SignupTemplate};
use crate::{axum::AxumAuthery, store::AutheryStore};

#[derive(Deserialize)]
pub struct NextMessageErrorQuery {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    /// An org invite code to apply once a signup/login flow completes.
    #[cfg(feature = "organizations")]
    pub invite: Option<String>,
}

#[derive(Deserialize)]
pub struct AddressMessageSentErrorQuery {
    pub address: Option<String>,
    pub message: Option<String>,
    pub sent: Option<bool>,
    pub error: Option<String>,
}

pub async fn get_login<St>(
    #[cfg_attr(not(feature = "organizations"), allow(unused_mut))] mut auth: AxumAuthery<St>,
    Query(query): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let NextMessageErrorQuery {
        next,
        message,
        error,
        ..
    } = &query;
    let (next, message, error) = (next.clone(), message.clone(), error.clone());

    #[cfg(feature = "organizations")]
    if let Some(invite) = query.invite.as_deref() {
        auth.org_set_invite_cookie(invite);
    }

    Ok(if auth.logged_in().await? {
        Redirect::to(&auth.routes.pages.post_login).into_response()
    } else {
        let view = LoginTemplate::with(&auth, next.as_deref(), message.as_deref(), error.as_deref());
        Html(auth.pages.render_login(&view)).into_response()
    })
}

pub async fn get_signup<St>(
    #[cfg_attr(not(feature = "organizations"), allow(unused_mut))] mut auth: AxumAuthery<St>,
    Query(query): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    #[cfg(feature = "organizations")]
    if let Some(invite) = query.invite.as_deref() {
        auth.org_set_invite_cookie(invite);
    }

    let view = SignupTemplate::with(
        &auth,
        query.next.as_deref(),
        query.message.as_deref(),
        query.error.as_deref(),
    );
    Ok(Html(auth.pages.render_signup(&view)).into_response())
}

/// The org-scoped login page: the regular login page constrained by the org's
/// login rules and extended with its own SSO providers.
#[cfg(all(feature = "organizations", feature = "oauth"))]
pub async fn get_org_login<St>(
    mut auth: AxumAuthery<St>,
    axum::extract::Path(org_slug): axum::extract::Path<String>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        invite,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::models::org::Organization;
    use axum::http::StatusCode;

    if let Some(invite) = invite.as_deref() {
        auth.org_set_invite_cookie(invite);
    }

    let Some(org) = auth.store.org_get_by_slug(&org_slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    if auth.logged_in().await? {
        return Ok(Redirect::to(&auth.routes.pages.post_login).into_response());
    }

    let org_providers = auth.store.org_oidc_list(&org.get_id()).await?;

    let view = LoginTemplate::with_org(
        &auth,
        &org,
        &org_providers,
        next.as_deref(),
        message.as_deref(),
        error.as_deref(),
    );
    Ok(Html(auth.pages.render_login(&view)).into_response())
}

#[cfg(feature = "mfa")]
pub async fn get_login_mfa<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::models::{LoginMethod, LoginSession};
    use crate::pages::MfaTemplate;

    let login_route = auth.routes.pages.login.clone();

    let Some(pending) = auth.mfa_pending_session().await? else {
        return Ok(Redirect::to(&login_route).into_response());
    };
    let LoginMethod::MfaPending { first } = pending.get_method() else {
        return Ok(Redirect::to(&login_route).into_response());
    };

    let factors = auth.mfa_factors(&pending.get_user_id(), &first).await?;

    let view = MfaTemplate {
        next: next.as_deref(),
        message: message.as_deref(),
        error: error.as_deref(),
        #[cfg(feature = "otp")]
        otp: factors.otp_address.map(|address| crate::pages::MfaOtpTemplateInfo {
            action_route: &auth.routes.mfa.login_mfa_otp,
            address_hint: mask_address(&address),
        }),
        #[cfg(not(feature = "otp"))]
        otp: None,
        #[cfg(feature = "webauthn")]
        webauthn: factors
            .webauthn
            .then_some(crate::pages::MfaWebauthnTemplateInfo {
                start_route: &auth.routes.mfa.login_mfa_webauthn_start,
                finish_route: &auth.routes.mfa.login_mfa_webauthn_finish,
            }),
        #[cfg(not(feature = "webauthn"))]
        webauthn: None,
    };

    Ok(Html(auth.pages.render_mfa(&view)).into_response())
}

/// `stefan@example.com` -> `s***@example.com`
#[cfg(all(feature = "mfa", feature = "otp"))]
fn mask_address(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().unwrap_or('*');
            format!("{first}***@{domain}")
        }
        None => "***".to_string(),
    }
}

#[cfg(feature = "otp")]
#[derive(Deserialize)]
pub struct OtpPageQuery {
    pub address: String,
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[cfg(feature = "otp")]
pub async fn get_login_otp<St>(
    auth: AxumAuthery<St>,
    Query(query): Query<OtpPageQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::OtpTemplate;

    let view = OtpTemplate {
        address: &query.address,
        action_route: &auth.routes.email.login_otp,
        next: query.next.as_deref(),
        message: query.message.as_deref(),
        error: query.error.as_deref(),
    };
    Ok(Html(auth.pages.render_otp(&view)))
}

#[cfg(feature = "otp")]
pub async fn get_signup_otp<St>(
    auth: AxumAuthery<St>,
    Query(query): Query<OtpPageQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::OtpTemplate;

    let view = OtpTemplate {
        address: &query.address,
        action_route: &auth.routes.email.signup_otp,
        next: query.next.as_deref(),
        message: query.message.as_deref(),
        error: query.error.as_deref(),
    };
    Ok(Html(auth.pages.render_otp(&view)))
}

#[cfg(feature = "user")]
pub async fn get_user<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::UserTemplate;
    use crate::models::User;

    let login_route = auth.routes.pages.login.clone();

    Ok(if let Some((user, session)) = auth.user_session().await? {
        let sessions = auth.store.get_user_sessions(&user.get_id()).await?;
        #[cfg(feature = "email")]
        let emails = auth.store.get_user_emails(&user.get_id()).await?;
        #[cfg(feature = "oauth")]
        let oauth_tokens = auth.store.get_user_oauth_tokens(&user.get_id()).await?;
        #[cfg(feature = "webauthn")]
        let passkey_credential_ids = auth
            .store
            .webauthn_get_credentials(&user.get_id())
            .await?
            .iter()
            .map(|p| p.cred_id().iter().map(|b| format!("{b:02x}")).collect())
            .collect();

        let view = UserTemplate::with(
            &auth,
            &user,
            &session,
            &sessions,
            message.as_deref(),
            error.as_deref(),
            #[cfg(feature = "email")]
            &emails,
            #[cfg(feature = "oauth")]
            &oauth_tokens,
            #[cfg(feature = "webauthn")]
            passkey_credential_ids,
        );
        Html(auth.pages.render_user(&view)).into_response()
    } else {
        Redirect::to(&format!("{login_route}?next=%2Fuser")).into_response()
    })
}

#[cfg(all(feature = "password", feature = "email"))]
pub async fn get_password_send_reset<St>(
    auth: AxumAuthery<St>,
    Query(query): Query<AddressMessageSentErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::SendResetPasswordTemplate;

    let view = SendResetPasswordTemplate {
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address.as_deref(),
        error: query.error.as_deref(),
        message: query.message.as_deref(),
        send_reset_password_action_route: &auth.routes.email.password_send_reset,
    };
    Ok(Html(auth.pages.render_send_reset_password(&view)))
}

#[cfg(all(feature = "email", feature = "password"))]
pub async fn get_password_reset<St>(auth: AxumAuthery<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use axum::http::StatusCode;
    use crate::pages::ResetPasswordTemplate;

    if auth.is_reset_session().await? {
        let view = ResetPasswordTemplate {
            reset_password_action_route: &auth.routes.email.password_reset,
        };
        Ok(Html(auth.pages.render_reset_password(&view)).into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

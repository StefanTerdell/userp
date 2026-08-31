use crate::pages::{LoginTemplate, SignupTemplate};
use crate::{axum::AxumAuthery, store::AutheryStore};
use axum::extract::Query;
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct NextMessageErrorQuery {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    /// Preselects that method's panel on the login/signup page.
    pub method: Option<String>,
}

#[derive(Deserialize)]
pub struct PausedQuery {
    pub retry_after: Option<i64>,
    pub next: Option<String>,
}

pub async fn get_paused<St>(
    auth: AxumAuthery<St>,
    Query(PausedQuery { retry_after, next }): Query<PausedQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::PausedTemplate;

    let view = PausedTemplate {
        retry_after_secs: retry_after,
        next: next.as_deref(),
        login_page_route: &auth.routes.pages.login,
        webauthn: cfg!(feature = "webauthn"),
        #[cfg(feature = "email")]
        email_login_action_route: auth
            .email
            .offer_links
            .then_some(auth.routes.email.login_email.as_str()),
        #[cfg(not(feature = "email"))]
        email_login_action_route: None,
        #[cfg(all(feature = "email", feature = "password"))]
        password_send_reset_page_route: Some(&auth.routes.pages.password_send_reset),
        #[cfg(not(all(feature = "email", feature = "password")))]
        password_send_reset_page_route: None,
    };
    Ok(Html(auth.pages.render_paused(&view)))
}

#[cfg(feature = "email")]
#[derive(Deserialize)]
pub struct EmailLinkQuery {
    pub address: Option<String>,
    pub purpose: Option<String>,
    pub next: Option<String>,
}

/// The resend and request-a-code actions for a link purpose.
#[cfg(feature = "email")]
fn email_link_actions<St: AutheryStore>(
    auth: &AxumAuthery<St>,
    purpose: crate::pages::EmailLinkPurpose,
) -> (Option<&str>, Option<&str>) {
    use crate::pages::EmailLinkPurpose;

    let routes = &auth.routes;
    let offer_otp = auth.email.offer_otp;
    match purpose {
        EmailLinkPurpose::Login => (
            Some(routes.email.login_email.as_str()),
            offer_otp.then_some(routes.email.login_otp.as_str()),
        ),
        EmailLinkPurpose::Signup => (
            Some(routes.email.signup_email.as_str()),
            offer_otp.then_some(routes.email.signup_otp.as_str()),
        ),
        EmailLinkPurpose::Verify => (None, None),
        #[cfg(feature = "password")]
        EmailLinkPurpose::Reset => (Some(routes.email.password_send_reset.as_str()), None),
        #[cfg(not(feature = "password"))]
        EmailLinkPurpose::Reset => (None, None),
    }
}

#[cfg(feature = "email")]
pub async fn get_email_sent<St>(
    auth: AxumAuthery<St>,
    Query(EmailLinkQuery {
        address,
        purpose,
        next,
    }): Query<EmailLinkQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::{EmailLinkPurpose, EmailSentTemplate};

    let Some(address) = address else {
        return Ok(Redirect::to(&auth.routes.pages.login).into_response());
    };
    let purpose = purpose
        .as_deref()
        .and_then(EmailLinkPurpose::parse)
        .unwrap_or(EmailLinkPurpose::Login);
    let (resend_action_route, otp_action_route) = email_link_actions(&auth, purpose);

    let view = EmailSentTemplate {
        address: &address,
        purpose,
        resend_action_route,
        otp_action_route,
        login_page_route: &auth.routes.pages.login,
        next: next.as_deref(),
    };
    Ok(Html(auth.pages.render_email_sent(&view)).into_response())
}

#[cfg(feature = "email")]
pub async fn get_email_expired<St>(
    auth: AxumAuthery<St>,
    Query(EmailLinkQuery {
        address, purpose, ..
    }): Query<EmailLinkQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::{EmailExpiredTemplate, EmailLinkPurpose};

    let purpose = purpose
        .as_deref()
        .and_then(EmailLinkPurpose::parse)
        .unwrap_or(EmailLinkPurpose::Login);
    let (resend_action_route, otp_action_route) = email_link_actions(&auth, purpose);

    let view = EmailExpiredTemplate {
        address: address.as_deref(),
        purpose,
        resend_action_route,
        otp_action_route,
        login_page_route: &auth.routes.pages.login,
        password: cfg!(feature = "password"),
        webauthn: cfg!(feature = "webauthn"),
    };
    Ok(Html(auth.pages.render_email_expired(&view)))
}

#[derive(Deserialize)]
pub struct AddressMessageSentErrorQuery {
    pub address: Option<String>,
    pub message: Option<String>,
    pub sent: Option<bool>,
    pub error: Option<String>,
}

pub async fn get_login<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        method,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        Redirect::to(&auth.routes.pages.post_login).into_response()
    } else {
        let view = LoginTemplate::with(
            &auth,
            next.as_deref(),
            message.as_deref(),
            error.as_deref(),
            method.as_deref(),
        );
        Html(auth.pages.render_login(&view)).into_response()
    })
}

pub async fn get_signup<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        method,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let view = SignupTemplate::with(
        &auth,
        next.as_deref(),
        message.as_deref(),
        error.as_deref(),
        method.as_deref(),
    );
    Ok(Html(auth.pages.render_signup(&view)).into_response())
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

    // Only a safe local path may reach the template: the passkey script
    // navigates to it after the second factor.
    let next = next.filter(|next| crate::axum::router::is_safe_next(next));

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
        trust_device_days: auth
            .mfa_policy
            .trusted_device_lifetime
            .map(|lifetime| lifetime.num_days().max(1)),
        #[cfg(feature = "email")]
        otp: factors
            .otp_address
            .map(|address| crate::pages::MfaOtpTemplateInfo {
                action_route: &auth.routes.mfa.login_mfa_otp,
                address_hint: mask_address(&address),
                code_input: crate::pages::CodeInputHints::from_generator(
                    auth.email.code_generator.as_ref(),
                ),
            }),
        #[cfg(not(feature = "email"))]
        otp: None,
        #[cfg(feature = "sms")]
        sms: factors
            .sms_number
            .map(|number| crate::pages::MfaSmsTemplateInfo {
                action_route: &auth.routes.mfa.login_mfa_sms,
                number_hint: mask_number(&number),
                code_input: crate::pages::CodeInputHints::from_generator(
                    auth.sms.code_generator.as_ref(),
                ),
            }),
        #[cfg(not(feature = "sms"))]
        sms: None,
        #[cfg(feature = "totp")]
        totp: factors
            .totp
            .then_some(auth.routes.mfa.login_mfa_totp.as_str()),
        #[cfg(not(feature = "totp"))]
        totp: None,
        recovery: factors
            .recovery_codes
            .then_some(auth.routes.mfa.login_mfa_recovery.as_str()),
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
#[cfg(all(feature = "mfa", feature = "email"))]
fn mask_address(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().unwrap_or('*');
            format!("{first}***@{domain}")
        }
        None => "***".to_string(),
    }
}

/// `+46701234567` -> `+46***67`
#[cfg(all(feature = "mfa", feature = "sms"))]
fn mask_number(number: &str) -> String {
    let prefix: String = number.chars().take(3).collect();
    let suffix: String = number
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}***{suffix}")
}

#[cfg(feature = "sms")]
pub async fn get_login_sms<St>(
    auth: AxumAuthery<St>,
    Query(query): Query<OtpPageQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::SmsTemplate;

    let view = SmsTemplate {
        login_page_route: &auth.routes.pages.login,
        number: &query.address,
        action_route: &auth.routes.sms.login_sms,
        next: query.next.as_deref(),
        message: query.message.as_deref(),
        error: query.error.as_deref(),
        code_input: crate::pages::CodeInputHints::from_generator(auth.sms.code_generator.as_ref()),
    };
    Ok(Html(auth.pages.render_sms(&view)))
}

#[cfg(feature = "sms")]
pub async fn get_signup_sms<St>(
    auth: AxumAuthery<St>,
    Query(query): Query<OtpPageQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::SmsTemplate;

    let view = SmsTemplate {
        login_page_route: &auth.routes.pages.login,
        number: &query.address,
        action_route: &auth.routes.sms.signup_sms,
        next: query.next.as_deref(),
        message: query.message.as_deref(),
        error: query.error.as_deref(),
        code_input: crate::pages::CodeInputHints::from_generator(auth.sms.code_generator.as_ref()),
    };
    Ok(Html(auth.pages.render_sms(&view)))
}

#[cfg(any(feature = "email", feature = "sms"))]
#[derive(Deserialize)]
pub struct OtpPageQuery {
    pub address: String,
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[cfg(feature = "email")]
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
        login_page_route: &auth.routes.pages.login,
        address: &query.address,
        action_route: &auth.routes.email.login_otp,
        next: query.next.as_deref(),
        message: query.message.as_deref(),
        error: query.error.as_deref(),
        code_input: crate::pages::CodeInputHints::from_generator(
            auth.email.code_generator.as_ref(),
        ),
    };
    Ok(Html(auth.pages.render_otp(&view)))
}

#[cfg(feature = "email")]
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
        login_page_route: &auth.routes.pages.login,
        address: &query.address,
        action_route: &auth.routes.email.signup_otp,
        next: query.next.as_deref(),
        message: query.message.as_deref(),
        error: query.error.as_deref(),
        code_input: crate::pages::CodeInputHints::from_generator(
            auth.email.code_generator.as_ref(),
        ),
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
    use crate::models::User;
    use crate::pages::UserTemplate;

    let login_route = auth.routes.pages.login.clone();

    Ok(if let Some((user, session)) = auth.user_session().await? {
        let sessions = auth.store.get_user_sessions(&user.get_id()).await?;
        #[cfg(feature = "email")]
        let emails = auth.store.get_user_emails(&user.get_id()).await?;
        #[cfg(feature = "oauth")]
        let oauth_tokens = auth.store.get_user_oauth_tokens(&user.get_id()).await?;
        #[cfg(feature = "webauthn")]
        let passkeys = auth.store.get_passkeys(&user.get_id()).await?;
        #[cfg(feature = "totp")]
        let totp_enabled = auth.totp_enabled(&user.get_id()).await?;
        #[cfg(feature = "mfa")]
        let recovery_codes_count = auth.store.count_recovery_codes(&user.get_id()).await?;

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
            &passkeys,
            #[cfg(feature = "totp")]
            totp_enabled,
            #[cfg(feature = "mfa")]
            recovery_codes_count,
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
        login_page_route: &auth.routes.pages.login,
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address.as_deref(),
        error: query.error.as_deref(),
        message: query.message.as_deref(),
        send_reset_password_action_route: &auth.routes.email.password_send_reset,
    };
    Ok(Html(auth.pages.render_send_reset_password(&view)))
}

#[cfg(all(feature = "email", feature = "password"))]
pub async fn get_password_reset<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery { error, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::ResetPasswordTemplate;
    use axum::http::StatusCode;

    if auth.is_reset_session().await? {
        let view = ResetPasswordTemplate {
            login_page_route: &auth.routes.pages.login,
            reset_password_action_route: &auth.routes.email.password_reset,
            error: error.as_deref(),
            pattern: auth.pass.pattern.as_ref().map(|p| p.pattern().to_owned()),
            pattern_hint: auth
                .pass
                .pattern
                .as_ref()
                .and_then(|p| p.hint().map(str::to_owned)),
        };
        Ok(Html(auth.pages.render_reset_password(&view)).into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

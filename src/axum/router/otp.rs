use crate::{
    axum::AxumAuthery,
    email::{SendEmailChallengeError, otp::OtpInitError, otp::OtpVerifyError},
    store::AutheryStore,
};
use axum::{
    Form,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};

/// One form serves both steps: without `code` it requests a code to be sent,
/// with `code` it verifies it.
#[derive(Debug, Serialize, Deserialize)]
pub struct OtpForm {
    pub email: String,
    pub code: Option<String>,
    pub next: Option<String>,
}

pub(crate) async fn post_login_otp<St>(
    auth: AxumAuthery<St>,
    Form(OtpForm { email, code, next }): Form<OtpForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let otp_route = auth.routes.email.login_otp.clone();
    let routes = auth.routes.clone();

    match code {
        None => match auth.otp_login_init(email.clone(), next.clone()).await {
            Ok(()) => Ok(Redirect::to(&format!(
                "{otp_route}?address={}&message=Code sent!",
                urlencoding::encode(&email)
            ))
            .into_response()),
            Err(OtpInitError::SendingEmail(SendEmailChallengeError::Store(err))) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &crate::axum::router::with_method(&routes.pages.login, "otp"),
                next.as_deref(),
            ))
            .into_response()),
        },
        Some(code) => match auth.otp_login_verify(&email, &code).await {
            Ok((auth, next)) => crate::axum::router::complete_login(auth, next).await,
            Err(OtpVerifyError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &format!("{otp_route}?address={}", urlencoding::encode(&email)),
                next.as_deref(),
            ))
            .into_response()),
        },
    }
}

pub(crate) async fn post_signup_otp<St>(
    auth: AxumAuthery<St>,
    Form(OtpForm { email, code, next }): Form<OtpForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let otp_route = auth.routes.email.signup_otp.clone();
    let routes = auth.routes.clone();

    match code {
        None => match auth.otp_signup_init(email.clone(), next.clone()).await {
            Ok(()) => Ok(Redirect::to(&format!(
                "{otp_route}?address={}&message=Code sent!",
                urlencoding::encode(&email)
            ))
            .into_response()),
            Err(OtpInitError::SendingEmail(SendEmailChallengeError::Store(err))) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &crate::axum::router::with_method(&routes.pages.signup, "otp"),
                next.as_deref(),
            ))
            .into_response()),
        },
        Some(code) => match auth.otp_signup_verify(&email, &code).await {
            Ok((auth, next)) => crate::axum::router::complete_login(auth, next).await,
            Err(OtpVerifyError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &format!("{otp_route}?address={}", urlencoding::encode(&email)),
                next.as_deref(),
            ))
            .into_response()),
        },
    }
}

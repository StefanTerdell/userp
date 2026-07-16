use axum::{
    response::{IntoResponse, Redirect},
    Form,
};
use serde::{Deserialize, Serialize};
use crate::{
    axum::AxumAuthery,
    email::{otp::OtpInitError, otp::OtpVerifyError, SendEmailChallengeError},
    store::AutheryStore,
};

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
    let login_route = auth.routes.pages.login.clone();

    match code {
        None => match auth.otp_login_init(email.clone(), next).await {
            Ok(()) => Ok(Redirect::to(&format!(
                "{otp_route}?address={}&message=Code sent!",
                urlencoding::encode(&email)
            ))
            .into_response()),
            Err(OtpInitError::SendingEmail(SendEmailChallengeError::Store(err))) => Err(err),
            Err(err) => Ok(Redirect::to(&format!(
                "{login_route}?error={}",
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        },
        Some(code) => match auth.otp_login_verify(&email, &code).await {
            Ok((auth, next)) => {
                #[cfg(feature = "mfa")]
                if auth.mfa_pending_session().await?.is_some() {
                    let url =
                        crate::axum::router::mfa::mfa_redirect_url(&auth.routes, next.as_deref());
                    return Ok((auth, Redirect::to(&url)).into_response());
                }

                let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
                Ok((auth, Redirect::to(&next)).into_response())
            }
            Err(OtpVerifyError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&format!(
                "{otp_route}?address={}&error={}",
                urlencoding::encode(&email),
                urlencoding::encode(&err.to_string())
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
    let signup_route = auth.routes.pages.signup.clone();

    match code {
        None => match auth.otp_signup_init(email.clone(), next).await {
            Ok(()) => Ok(Redirect::to(&format!(
                "{otp_route}?address={}&message=Code sent!",
                urlencoding::encode(&email)
            ))
            .into_response()),
            Err(OtpInitError::SendingEmail(SendEmailChallengeError::Store(err))) => Err(err),
            Err(err) => Ok(Redirect::to(&format!(
                "{signup_route}?error={}",
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        },
        Some(code) => match auth.otp_signup_verify(&email, &code).await {
            Ok((auth, next)) => {
                #[cfg(feature = "mfa")]
                if auth.mfa_pending_session().await?.is_some() {
                    let url =
                        crate::axum::router::mfa::mfa_redirect_url(&auth.routes, next.as_deref());
                    return Ok((auth, Redirect::to(&url)).into_response());
                }

                let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
                Ok((auth, Redirect::to(&next)).into_response())
            }
            Err(OtpVerifyError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&format!(
                "{otp_route}?address={}&error={}",
                urlencoding::encode(&email),
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        },
    }
}

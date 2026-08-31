use crate::{axum::AxumAuthery, sms::SmsVerifyError, store::AutheryStore};
use axum::{
    Form,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};

/// One form serves both steps: without `code` it requests a code to be sent,
/// with `code` it verifies it.
#[derive(Debug, Serialize, Deserialize)]
pub struct SmsForm {
    pub number: String,
    pub code: Option<String>,
    pub next: Option<String>,
}

pub(crate) async fn post_login_sms<St>(
    auth: AxumAuthery<St>,
    Form(SmsForm { number, code, next }): Form<SmsForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let sms_route = auth.routes.sms.login_sms.clone();
    let routes = auth.routes.clone();

    match code {
        None => match auth.sms_login_init(number.clone(), next.clone()).await {
            Ok(()) => Ok(Redirect::to(&format!(
                "{sms_route}?address={}&message=Code sent!",
                urlencoding::encode(&number)
            ))
            .into_response()),
            Err(crate::sms::SmsInitError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &crate::axum::router::with_method(&routes.pages.login, "sms"),
                next.as_deref(),
            ))
            .into_response()),
        },
        Some(code) => match auth.sms_login_verify(&number, &code).await {
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
            Err(SmsVerifyError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &format!("{sms_route}?address={}", urlencoding::encode(&number)),
                next.as_deref(),
            ))
            .into_response()),
        },
    }
}

pub(crate) async fn post_signup_sms<St>(
    auth: AxumAuthery<St>,
    Form(SmsForm { number, code, next }): Form<SmsForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let sms_route = auth.routes.sms.signup_sms.clone();
    let routes = auth.routes.clone();

    match code {
        None => match auth.sms_signup_init(number.clone(), next.clone()).await {
            Ok(()) => Ok(Redirect::to(&format!(
                "{sms_route}?address={}&message=Code sent!",
                urlencoding::encode(&number)
            ))
            .into_response()),
            Err(crate::sms::SmsInitError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &crate::axum::router::with_method(&routes.pages.signup, "sms"),
                next.as_deref(),
            ))
            .into_response()),
        },
        Some(code) => match auth.sms_signup_verify(&number, &code).await {
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
            Err(SmsVerifyError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &format!("{sms_route}?address={}", urlencoding::encode(&number)),
                next.as_deref(),
            ))
            .into_response()),
        },
    }
}

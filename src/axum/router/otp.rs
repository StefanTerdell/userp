use crate::{axum::AxumAuthery, email::otp::EmailOtpFlow, models::Intent, store::AutheryStore};
use axum::{Form, response::IntoResponse};
use serde::{Deserialize, Serialize};

/// One form serves both steps: without `code` it requests a code to be sent,
/// with `code` it verifies it. An empty `code` counts as absent.
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
    let route = auth.routes.email.login_otp.clone();
    crate::axum::router::post_code_flow::<St, EmailOtpFlow>(
        auth,
        email,
        code,
        next,
        Intent::LogIn,
        route,
        "otp",
    )
    .await
}

pub(crate) async fn post_signup_otp<St>(
    auth: AxumAuthery<St>,
    Form(OtpForm { email, code, next }): Form<OtpForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let route = auth.routes.email.signup_otp.clone();
    crate::axum::router::post_code_flow::<St, EmailOtpFlow>(
        auth,
        email,
        code,
        next,
        Intent::SignUp,
        route,
        "otp",
    )
    .await
}

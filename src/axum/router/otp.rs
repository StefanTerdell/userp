use crate::axum::extract::FormOrJson;
use crate::axum::response::StoreFailure;
use crate::{axum::AxumAuthery, email::otp::EmailOtpFlow, models::Intent, store::AutheryStore};
use axum::response::Response;
use serde::{Deserialize, Serialize};

/// One form serves both steps: without `code` it requests a code to be sent,
/// with `code` it verifies it. An empty `code` counts as absent.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct OtpForm {
    /// The address the code is sent to, and verified against.
    pub email: String,
    /// The code from the message; omit it to have one sent.
    pub code: Option<String>,
    /// Where to send the browser afterwards; must be a local path.
    pub next: Option<String>,
}

pub(crate) async fn post_login_otp<St>(
    auth: AxumAuthery<St>,
    FormOrJson(OtpForm { email, code, next }): FormOrJson<OtpForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
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
    FormOrJson(OtpForm { email, code, next }): FormOrJson<OtpForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
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

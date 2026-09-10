use crate::axum::extract::FormOrJson;
use crate::axum::response::StoreFailure;
use crate::{axum::AxumAuthery, models::Intent, sms::SmsFlow, store::AutheryStore};
use axum::response::Response;
use serde::{Deserialize, Serialize};

/// One form serves both steps: without `code` it requests a code to be sent,
/// with `code` it verifies it. An empty `code` counts as absent.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct SmsForm {
    /// The phone number in E.164 form.
    pub number: String,
    /// The code from the text; omit it to have one sent.
    pub code: Option<String>,
    /// Where to send the browser afterwards; must be a local path.
    pub next: Option<String>,
}

pub(crate) async fn post_login_sms<St>(
    auth: AxumAuthery<St>,
    FormOrJson(SmsForm { number, code, next }): FormOrJson<SmsForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let route = auth.routes.sms.login_sms.clone();
    crate::axum::router::post_code_flow::<St, SmsFlow>(
        auth,
        number,
        code,
        next,
        Intent::LogIn,
        route,
        "sms",
    )
    .await
}

pub(crate) async fn post_signup_sms<St>(
    auth: AxumAuthery<St>,
    FormOrJson(SmsForm { number, code, next }): FormOrJson<SmsForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let route = auth.routes.sms.signup_sms.clone();
    crate::axum::router::post_code_flow::<St, SmsFlow>(
        auth,
        number,
        code,
        next,
        Intent::SignUp,
        route,
        "sms",
    )
    .await
}

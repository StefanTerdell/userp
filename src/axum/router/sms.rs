use crate::{axum::AxumAuthery, models::Intent, sms::SmsFlow, store::AutheryStore};
use axum::{Form, response::IntoResponse};
use serde::{Deserialize, Serialize};

/// One form serves both steps: without `code` it requests a code to be sent,
/// with `code` it verifies it. An empty `code` counts as absent.
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
    Form(SmsForm { number, code, next }): Form<SmsForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
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

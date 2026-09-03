use crate::{axum::AxumAuthery, routes::Routes, store::AutheryStore};
use axum::response::{IntoResponse, Redirect};

/// A non-empty `trust_device` form/query value opts the device in.
fn wants_trust(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|v| !v.is_empty())
}

/// Where to send a browser that has a pending MFA session, preserving `next`.
pub(crate) fn mfa_redirect_url(routes: &Routes<String>, next: Option<&str>) -> String {
    match next {
        Some(next) => format!(
            "{}?next={}",
            routes.mfa.login_mfa,
            urlencoding::encode(next)
        ),
        None => routes.mfa.login_mfa.clone(),
    }
}

/// The MFA page with a query pair appended, preserving `next`.
#[cfg(any(feature = "email", feature = "sms"))]
fn mfa_url_with(routes: &Routes<String>, key: &str, value: &str, next: Option<&str>) -> String {
    let mut url = format!(
        "{}?{key}={}",
        routes.mfa.login_mfa,
        urlencoding::encode(value)
    );
    if let Some(next) = next {
        url.push_str(&format!("&next={}", urlencoding::encode(next)));
    }
    url
}

/// Complete a verified second factor: trust the device when asked, then
/// redirect to the sanitized `next`.
async fn finish_mfa<St>(
    mut auth: AxumAuthery<St>,
    next: Option<String>,
    trust_device: Option<String>,
) -> Result<axum::response::Response, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    if wants_trust(&trust_device) {
        auth.trust_this_device().await?;
    }
    let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
    Ok((auth, Redirect::to(&next)).into_response())
}

/// One form serves both steps: without `code` it requests a code to be sent,
/// with `code` it verifies it. An empty `code` counts as absent.
#[cfg(any(feature = "email", feature = "sms"))]
#[derive(serde::Deserialize)]
pub(crate) struct MfaCodeForm {
    pub code: Option<String>,
    pub next: Option<String>,
    pub trust_device: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct MfaVerifyForm {
    pub code: String,
    pub next: Option<String>,
    pub trust_device: Option<String>,
}

#[cfg(feature = "email")]
pub(crate) use otp_factor::post_login_mfa_otp;

#[cfg(feature = "email")]
mod otp_factor {
    use super::*;
    use crate::mfa::MfaOtpError;
    use axum::Form;

    /// Without `code`: mail a code to the pending user's verified address.
    /// With `code`: verify it and complete the login.
    pub(crate) async fn post_login_mfa_otp<St>(
        auth: AxumAuthery<St>,
        Form(MfaCodeForm {
            code,
            next,
            trust_device,
        }): Form<MfaCodeForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let login_route = auth.routes.pages.login.clone();
        let routes = auth.routes.clone();

        match code.filter(|code| !code.is_empty()) {
            None => match auth.mfa_otp_init().await {
                Ok(_address) => Ok(Redirect::to(&mfa_url_with(
                    &routes,
                    "message",
                    "Code sent!",
                    next.as_deref(),
                ))
                .into_response()),
                Err(MfaOtpError::Store(err)) => Err(err),
                Err(MfaOtpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    &err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                ))
                .into_response()),
            },
            Some(code) => match auth.mfa_otp_verify(&code).await {
                Ok(auth) => finish_mfa(auth, next, trust_device).await,
                Err(MfaOtpError::Store(err)) => Err(err),
                Err(MfaOtpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    &err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                ))
                .into_response()),
            },
        }
    }
}

#[cfg(feature = "webauthn")]
pub(crate) use webauthn_factor::{post_login_mfa_webauthn_finish, post_login_mfa_webauthn_start};

#[cfg(feature = "webauthn")]
mod webauthn_factor {
    use super::*;
    use crate::mfa::MfaWebauthnError;
    use axum::{Json, http::StatusCode};
    use serde_json::json;
    use webauthn_rs::prelude::PublicKeyCredential;

    pub(crate) async fn post_login_mfa_webauthn_start<St>(
        mut auth: AxumAuthery<St>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        match auth.mfa_webauthn_start().await {
            Ok(rcr) => Ok((auth, Json(rcr)).into_response()),
            Err(MfaWebauthnError::Store(err)) => Err(err),
            Err(err) => Ok(crate::axum::router::json_error(
                StatusCode::BAD_REQUEST,
                &err,
            )),
        }
    }

    #[derive(serde::Deserialize)]
    pub struct TrustQuery {
        pub trust_device: Option<String>,
    }

    pub(crate) async fn post_login_mfa_webauthn_finish<St>(
        auth: AxumAuthery<St>,
        axum::extract::Query(TrustQuery { trust_device }): axum::extract::Query<TrustQuery>,
        Json(credential): Json<PublicKeyCredential>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let post_login = auth.routes.pages.post_login.clone();

        match auth.mfa_webauthn_finish(&credential).await {
            Ok(mut auth) => {
                if wants_trust(&trust_device) {
                    auth.trust_this_device().await?;
                }
                Ok((auth, Json(json!({"next": post_login}))).into_response())
            }
            Err(MfaWebauthnError::Store(err)) => Err(err),
            Err(err) => Ok(crate::axum::router::json_error(
                StatusCode::UNAUTHORIZED,
                &err,
            )),
        }
    }
}

#[cfg(feature = "totp")]
pub(crate) use totp_factor::post_login_mfa_totp;

#[cfg(feature = "totp")]
mod totp_factor {
    use super::*;
    use crate::mfa::MfaTotpError;
    use axum::Form;

    /// Verify an authenticator-app code and complete the login.
    pub(crate) async fn post_login_mfa_totp<St>(
        auth: AxumAuthery<St>,
        Form(MfaVerifyForm {
            code,
            next,
            trust_device,
        }): Form<MfaVerifyForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let login_route = auth.routes.pages.login.clone();
        let routes = auth.routes.clone();

        match auth.mfa_totp_verify(&code).await {
            Ok(auth) => finish_mfa(auth, next, trust_device).await,
            Err(MfaTotpError::Store(err)) => Err(err),
            Err(MfaTotpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &mfa_redirect_url(&routes, next.as_deref()),
                next.as_deref(),
            ))
            .into_response()),
        }
    }
}

#[cfg(feature = "sms")]
pub(crate) use sms_factor::post_login_mfa_sms;

#[cfg(feature = "sms")]
mod sms_factor {
    use super::*;
    use crate::mfa::MfaSmsError;
    use axum::Form;

    /// Without `code`: text a code to the pending user's verified number.
    /// With `code`: verify it and complete the login.
    pub(crate) async fn post_login_mfa_sms<St>(
        auth: AxumAuthery<St>,
        Form(MfaCodeForm {
            code,
            next,
            trust_device,
        }): Form<MfaCodeForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let login_route = auth.routes.pages.login.clone();
        let routes = auth.routes.clone();

        match code.filter(|code| !code.is_empty()) {
            None => match auth.mfa_sms_init().await {
                Ok(_number) => Ok(Redirect::to(&mfa_url_with(
                    &routes,
                    "message",
                    "Code sent!",
                    next.as_deref(),
                ))
                .into_response()),
                Err(MfaSmsError::Store(err)) => Err(err),
                Err(MfaSmsError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    &err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                ))
                .into_response()),
            },
            Some(code) => match auth.mfa_sms_verify(&code).await {
                Ok(auth) => finish_mfa(auth, next, trust_device).await,
                Err(MfaSmsError::Store(err)) => Err(err),
                Err(MfaSmsError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    &err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                ))
                .into_response()),
            },
        }
    }
}

pub(crate) use recovery_factor::post_login_mfa_recovery;

mod recovery_factor {
    use super::*;
    use crate::mfa::MfaRecoveryError;
    use axum::Form;

    /// Consume a single-use recovery code and complete the login.
    pub(crate) async fn post_login_mfa_recovery<St>(
        auth: AxumAuthery<St>,
        Form(MfaVerifyForm {
            code,
            next,
            trust_device,
        }): Form<MfaVerifyForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let login_route = auth.routes.pages.login.clone();
        let routes = auth.routes.clone();

        match auth.mfa_recovery_verify(&code).await {
            Ok(auth) => finish_mfa(auth, next, trust_device).await,
            Err(MfaRecoveryError::Store(err)) => Err(err),
            Err(MfaRecoveryError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &mfa_redirect_url(&routes, next.as_deref()),
                next.as_deref(),
            ))
            .into_response()),
        }
    }
}

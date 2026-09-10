use crate::axum::response::{ApiError, FlowResult, StoreFailure};
use crate::{axum::AxumAuthery, routes::Routes, store::AutheryStore};
use axum::response::{IntoResponse, Redirect, Response};

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
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
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
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub(crate) struct MfaCodeForm {
    /// The code from the message; omit it to have one sent.
    pub code: Option<String>,
    /// Where to send the browser afterwards; must be a local path.
    pub next: Option<String>,
    /// Any non-empty value marks this browser as trusted.
    pub trust_device: Option<String>,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub(crate) struct MfaVerifyForm {
    /// The second-factor code to verify.
    pub code: String,
    /// Where to send the browser afterwards; must be a local path.
    pub next: Option<String>,
    /// Any non-empty value marks this browser as trusted.
    pub trust_device: Option<String>,
}

#[cfg(feature = "email")]
pub(crate) use otp_factor::post_login_mfa_otp;

#[cfg(feature = "email")]
mod otp_factor {
    use super::*;
    use crate::axum::extract::FormOrJson;
    use crate::mfa::MfaOtpError;

    /// Without `code`: mail a code to the pending user's verified address.
    /// With `code`: verify it and complete the login.
    pub(crate) async fn post_login_mfa_otp<St>(
        auth: AxumAuthery<St>,
        FormOrJson(MfaCodeForm {
            code,
            next,
            trust_device,
        }): FormOrJson<MfaCodeForm>,
    ) -> Result<Response, StoreFailure<St::Error>>
    where
        St: AutheryStore,
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
                Err(MfaOtpError::Store(err)) => Err(err.into()),
                Err(MfaOtpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                )?)
                .into_response()),
            },
            Some(code) => match auth.mfa_otp_verify(&code).await {
                Ok(auth) => finish_mfa(auth, next, trust_device).await,
                Err(MfaOtpError::Store(err)) => Err(err.into()),
                Err(MfaOtpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                )?)
                .into_response()),
            },
        }
    }
}

#[cfg(all(feature = "webauthn", feature = "openapi"))]
pub(crate) use webauthn_factor::TrustQuery;
#[cfg(feature = "webauthn")]
pub(crate) use webauthn_factor::{post_login_mfa_webauthn_finish, post_login_mfa_webauthn_start};

#[cfg(feature = "webauthn")]
mod webauthn_factor {
    use super::*;
    use crate::axum::extract::WebauthnJson;
    use crate::mfa::MfaWebauthnError;
    use axum::{Json, http::StatusCode};
    use webauthn_rs::prelude::PublicKeyCredential;

    pub(crate) async fn post_login_mfa_webauthn_start<St>(
        mut auth: AxumAuthery<St>,
    ) -> Result<Response, StoreFailure<St::Error>>
    where
        St: AutheryStore,
    {
        match auth.mfa_webauthn_start().await {
            Ok(rcr) => Ok((auth, Json(rcr)).into_response()),
            Err(MfaWebauthnError::Store(err)) => Err(err.into()),
            Err(err) => Ok(ApiError::response(StatusCode::BAD_REQUEST, &err)),
        }
    }

    #[derive(serde::Deserialize)]
    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
    pub struct TrustQuery {
        /// Any non-empty value marks this browser as trusted.
        pub trust_device: Option<String>,
    }

    pub(crate) async fn post_login_mfa_webauthn_finish<St>(
        auth: AxumAuthery<St>,
        axum::extract::Query(TrustQuery { trust_device }): axum::extract::Query<TrustQuery>,
        WebauthnJson(credential): WebauthnJson<PublicKeyCredential>,
    ) -> Result<Response, StoreFailure<St::Error>>
    where
        St: AutheryStore,
    {
        let post_login = auth.routes.pages.post_login.clone();

        match auth.mfa_webauthn_finish(&credential).await {
            Ok(mut auth) => {
                if wants_trust(&trust_device) {
                    auth.trust_this_device().await?;
                }
                Ok((
                    auth,
                    Json(FlowResult {
                        next: post_login,
                        message: None,
                    }),
                )
                    .into_response())
            }
            Err(MfaWebauthnError::Store(err)) => Err(err.into()),
            Err(err) => Ok(ApiError::response(StatusCode::UNAUTHORIZED, &err)),
        }
    }
}

#[cfg(feature = "totp")]
pub(crate) use totp_factor::post_login_mfa_totp;

#[cfg(feature = "totp")]
mod totp_factor {
    use super::*;
    use crate::axum::extract::FormOrJson;
    use crate::mfa::MfaTotpError;

    /// Verify an authenticator-app code and complete the login.
    pub(crate) async fn post_login_mfa_totp<St>(
        auth: AxumAuthery<St>,
        FormOrJson(MfaVerifyForm {
            code,
            next,
            trust_device,
        }): FormOrJson<MfaVerifyForm>,
    ) -> Result<Response, StoreFailure<St::Error>>
    where
        St: AutheryStore,
    {
        let login_route = auth.routes.pages.login.clone();
        let routes = auth.routes.clone();

        match auth.mfa_totp_verify(&code).await {
            Ok(auth) => finish_mfa(auth, next, trust_device).await,
            // Both spellings of a store failure: the store's own words never
            // reach the redirect.
            Err(MfaTotpError::Store(err))
            | Err(MfaTotpError::Totp(crate::totp::TotpError::Store(err))) => Err(err.into()),
            Err(MfaTotpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                err,
                &mfa_redirect_url(&routes, next.as_deref()),
                next.as_deref(),
            )?)
            .into_response()),
        }
    }
}

#[cfg(feature = "sms")]
pub(crate) use sms_factor::post_login_mfa_sms;

#[cfg(feature = "sms")]
mod sms_factor {
    use super::*;
    use crate::axum::extract::FormOrJson;
    use crate::mfa::MfaSmsError;

    /// Without `code`: text a code to the pending user's verified number.
    /// With `code`: verify it and complete the login.
    pub(crate) async fn post_login_mfa_sms<St>(
        auth: AxumAuthery<St>,
        FormOrJson(MfaCodeForm {
            code,
            next,
            trust_device,
        }): FormOrJson<MfaCodeForm>,
    ) -> Result<Response, StoreFailure<St::Error>>
    where
        St: AutheryStore,
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
                Err(MfaSmsError::Store(err)) => Err(err.into()),
                Err(MfaSmsError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                )?)
                .into_response()),
            },
            Some(code) => match auth.mfa_sms_verify(&code).await {
                Ok(auth) => finish_mfa(auth, next, trust_device).await,
                Err(MfaSmsError::Store(err)) => Err(err.into()),
                Err(MfaSmsError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    err,
                    &mfa_redirect_url(&routes, next.as_deref()),
                    next.as_deref(),
                )?)
                .into_response()),
            },
        }
    }
}

pub(crate) use recovery_factor::post_login_mfa_recovery;

mod recovery_factor {
    use super::*;
    use crate::axum::extract::FormOrJson;
    use crate::mfa::MfaRecoveryError;

    /// Consume a single-use recovery code and complete the login.
    pub(crate) async fn post_login_mfa_recovery<St>(
        auth: AxumAuthery<St>,
        FormOrJson(MfaVerifyForm {
            code,
            next,
            trust_device,
        }): FormOrJson<MfaVerifyForm>,
    ) -> Result<Response, StoreFailure<St::Error>>
    where
        St: AutheryStore,
    {
        let login_route = auth.routes.pages.login.clone();
        let routes = auth.routes.clone();

        match auth.mfa_recovery_verify(&code).await {
            Ok(auth) => finish_mfa(auth, next, trust_device).await,
            Err(MfaRecoveryError::Store(err)) => Err(err.into()),
            Err(MfaRecoveryError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
            Err(err) => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                err,
                &mfa_redirect_url(&routes, next.as_deref()),
                next.as_deref(),
            )?)
            .into_response()),
        }
    }
}

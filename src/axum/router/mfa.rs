use crate::{axum::AxumAuthery, routes::Routes, store::AutheryStore};
use axum::response::{IntoResponse, Redirect};

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

#[cfg(feature = "otp")]
pub(crate) use otp_factor::post_login_mfa_otp;

#[cfg(feature = "otp")]
mod otp_factor {
    use super::*;
    use crate::mfa::MfaOtpError;
    use axum::Form;
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct MfaOtpForm {
        pub code: Option<String>,
        pub next: Option<String>,
    }

    /// Without `code`: mail a code to the pending user's verified address.
    /// With `code`: verify it and complete the login.
    pub(crate) async fn post_login_mfa_otp<St>(
        auth: AxumAuthery<St>,
        Form(MfaOtpForm { code, next }): Form<MfaOtpForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let mfa_route = auth.routes.mfa.login_mfa.clone();
        let login_route = auth.routes.pages.login.clone();

        let with_query = |key: &str, value: &str| {
            let mut url = format!("{mfa_route}?{key}={}", urlencoding::encode(value));
            if let Some(next) = next.as_deref() {
                url.push_str(&format!("&next={}", urlencoding::encode(next)));
            }
            url
        };

        match code {
            None => match auth.mfa_otp_init().await {
                Ok(_address) => {
                    Ok(Redirect::to(&with_query("message", "Code sent!")).into_response())
                }
                Err(MfaOtpError::Store(err)) => Err(err),
                Err(MfaOtpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => {
                    Ok(Redirect::to(&with_query("error", &err.to_string())).into_response())
                }
            },
            Some(code) => match auth.mfa_otp_verify(&code).await {
                Ok(auth) => {
                    let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
                    Ok((auth, Redirect::to(&next)).into_response())
                }
                Err(MfaOtpError::Store(err)) => Err(err),
                Err(MfaOtpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => {
                    Ok(Redirect::to(&with_query("error", &err.to_string())).into_response())
                }
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
            Err(err) => Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": err.to_string()})),
            )
                .into_response()),
        }
    }

    pub(crate) async fn post_login_mfa_webauthn_finish<St>(
        auth: AxumAuthery<St>,
        Json(credential): Json<PublicKeyCredential>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let post_login = auth.routes.pages.post_login.clone();

        match auth.mfa_webauthn_finish(&credential).await {
            Ok(auth) => Ok((auth, Json(json!({"next": post_login}))).into_response()),
            Err(MfaWebauthnError::Store(err)) => Err(err),
            Err(err) => Ok((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": err.to_string()})),
            )
                .into_response()),
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
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct MfaTotpForm {
        pub code: String,
        pub next: Option<String>,
    }

    /// Verify an authenticator-app code and complete the login.
    pub(crate) async fn post_login_mfa_totp<St>(
        auth: AxumAuthery<St>,
        Form(MfaTotpForm { code, next }): Form<MfaTotpForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let mfa_route = auth.routes.mfa.login_mfa.clone();
        let login_route = auth.routes.pages.login.clone();

        match auth.mfa_totp_verify(&code).await {
            Ok(auth) => {
                let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
                Ok((auth, Redirect::to(&next)).into_response())
            }
            Err(MfaTotpError::Store(err)) => Err(err),
            Err(MfaTotpError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
            Err(err) => {
                let mut url = format!(
                    "{mfa_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                if let Some(next) = next.as_deref() {
                    url.push_str(&format!("&next={}", urlencoding::encode(next)));
                }
                Ok(Redirect::to(&url).into_response())
            }
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
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct MfaSmsForm {
        pub code: Option<String>,
        pub next: Option<String>,
    }

    /// Without `code`: text a code to the pending user's verified number.
    /// With `code`: verify it and complete the login.
    pub(crate) async fn post_login_mfa_sms<St>(
        auth: AxumAuthery<St>,
        Form(MfaSmsForm { code, next }): Form<MfaSmsForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let mfa_route = auth.routes.mfa.login_mfa.clone();
        let login_route = auth.routes.pages.login.clone();

        let with_query = |key: &str, value: &str| {
            let mut url = format!("{mfa_route}?{key}={}", urlencoding::encode(value));
            if let Some(next) = next.as_deref() {
                url.push_str(&format!("&next={}", urlencoding::encode(next)));
            }
            url
        };

        match code.filter(|code| !code.is_empty()) {
            None => match auth.mfa_sms_init().await {
                Ok(_number) => {
                    Ok(Redirect::to(&with_query("message", "Code sent!")).into_response())
                }
                Err(MfaSmsError::Store(err)) => Err(err),
                Err(MfaSmsError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => {
                    Ok(Redirect::to(&with_query("error", &err.to_string())).into_response())
                }
            },
            Some(code) => match auth.mfa_sms_verify(&code).await {
                Ok(auth) => {
                    let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
                    Ok((auth, Redirect::to(&next)).into_response())
                }
                Err(MfaSmsError::Store(err)) => Err(err),
                Err(MfaSmsError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
                Err(err) => {
                    Ok(Redirect::to(&with_query("error", &err.to_string())).into_response())
                }
            },
        }
    }
}

pub(crate) use recovery_factor::post_login_mfa_recovery;

mod recovery_factor {
    use super::*;
    use crate::mfa::MfaRecoveryError;
    use axum::Form;
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct MfaRecoveryForm {
        pub code: String,
        pub next: Option<String>,
    }

    /// Consume a single-use recovery code and complete the login.
    pub(crate) async fn post_login_mfa_recovery<St>(
        auth: AxumAuthery<St>,
        Form(MfaRecoveryForm { code, next }): Form<MfaRecoveryForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let mfa_route = auth.routes.mfa.login_mfa.clone();
        let login_route = auth.routes.pages.login.clone();

        match auth.mfa_recovery_verify(&code).await {
            Ok(auth) => {
                let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
                Ok((auth, Redirect::to(&next)).into_response())
            }
            Err(MfaRecoveryError::Store(err)) => Err(err),
            Err(MfaRecoveryError::NoPending) => Ok(Redirect::to(&login_route).into_response()),
            Err(err) => {
                let mut url = format!(
                    "{mfa_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                if let Some(next) = next.as_deref() {
                    url.push_str(&format!("&next={}", urlencoding::encode(next)));
                }
                Ok(Redirect::to(&url).into_response())
            }
        }
    }
}

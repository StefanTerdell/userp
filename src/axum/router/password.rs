use crate::{
    axum::AxumAuthery,
    password::{login::PasswordLoginError, signup::PasswordSignupError},
    store::AutheryStore,
};
use axum::{
    Form,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordIdNextForm {
    pub password_id: String,
    pub password: String,
    pub next: Option<String>,
}

pub(crate) async fn post_signup_password<St>(
    auth: AxumAuthery<St>,
    Form(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): Form<PasswordIdNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.password_signup(&email, &password).await {
        Ok(auth) => {
            #[cfg(feature = "mfa")]
            if auth.mfa_pending_session().await?.is_some() {
                let url = crate::axum::router::mfa::mfa_redirect_url(&auth.routes, next.as_deref());
                return Ok((auth, Redirect::to(&url)).into_response());
            }

            let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            PasswordSignupError::StoreError(err) => Err(err),
            _ => {
                let next = format!(
                    "{signup_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

pub(crate) async fn post_login_password<St>(
    auth: AxumAuthery<St>,
    Form(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): Form<PasswordIdNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.password_login(&email, &password).await {
        Ok(auth) => {
            #[cfg(feature = "mfa")]
            if auth.mfa_pending_session().await?.is_some() {
                let url = crate::axum::router::mfa::mfa_redirect_url(&auth.routes, next.as_deref());
                return Ok((auth, Redirect::to(&url)).into_response());
            }

            let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            PasswordLoginError::StoreError(err) => Err(err),
            PasswordLoginError::NotAllowed
            | PasswordLoginError::WrongPassword
            | PasswordLoginError::RateLimited(_) => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

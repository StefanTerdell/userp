use crate::axum::extract::FormOrJson;
use crate::axum::response::StoreFailure;
use crate::{
    axum::AxumAuthery,
    password::{login::PasswordLoginError, signup::PasswordSignupError},
    store::AutheryStore,
};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct PasswordIdNextForm {
    /// The password identifier, typically the user's email address.
    pub password_id: String,
    /// The password.
    pub password: String,
    /// Where to send the browser afterwards; must be a local path.
    pub next: Option<String>,
}

pub(crate) async fn post_signup_password<St>(
    auth: AxumAuthery<St>,
    FormOrJson(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): FormOrJson<PasswordIdNextForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let routes = auth.routes.clone();

    match auth.password_signup(&email, &password).await {
        Ok(auth) => crate::axum::router::complete_login(auth, next).await,
        Err(err) => match err {
            PasswordSignupError::StoreError(err) => Err(err.into()),
            _ => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                err,
                &crate::axum::router::with_method(&routes.pages.signup, "password"),
                next.as_deref(),
            )?)
            .into_response()),
        },
    }
}

pub(crate) async fn post_login_password<St>(
    auth: AxumAuthery<St>,
    FormOrJson(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): FormOrJson<PasswordIdNextForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let routes = auth.routes.clone();

    match auth.password_login(&email, &password).await {
        Ok(auth) => crate::axum::router::complete_login(auth, next).await,
        Err(err) => match err {
            PasswordLoginError::StoreError(err) => Err(err.into()),
            PasswordLoginError::NotAllowed
            | PasswordLoginError::WrongPassword
            | PasswordLoginError::RateLimited(_) => {
                Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    err,
                    &crate::axum::router::with_method(&routes.pages.login, "password"),
                    next.as_deref(),
                )?)
                .into_response())
            }
        },
    }
}

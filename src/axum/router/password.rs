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
    let routes = auth.routes.clone();

    match auth.password_signup(&email, &password).await {
        Ok(auth) => crate::axum::router::complete_login(auth, next).await,
        Err(err) => match err {
            PasswordSignupError::StoreError(err) => Err(err),
            _ => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &crate::axum::router::with_method(&routes.pages.signup, "password"),
                next.as_deref(),
            ))
            .into_response()),
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
    let routes = auth.routes.clone();

    match auth.password_login(&email, &password).await {
        Ok(auth) => crate::axum::router::complete_login(auth, next).await,
        Err(err) => match err {
            PasswordLoginError::StoreError(err) => Err(err),
            PasswordLoginError::NotAllowed
            | PasswordLoginError::WrongPassword
            | PasswordLoginError::RateLimited(_) => {
                Ok(Redirect::to(&crate::axum::router::error_redirect(
                    &routes,
                    &err,
                    &crate::axum::router::with_method(&routes.pages.login, "password"),
                    next.as_deref(),
                ))
                .into_response())
            }
        },
    }
}

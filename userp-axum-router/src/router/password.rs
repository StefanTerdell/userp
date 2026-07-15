use axum::{
    response::{IntoResponse, Redirect},
    Form,
};
use serde::{Deserialize, Serialize};
use userp_server::{
    axum::AxumUserp,
    password::{login::PasswordLoginError, signup::PasswordSignupError},
    store::UserpStore,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordIdNextForm {
    pub password_id: String,
    pub password: String,
    pub next: Option<String>,
}

pub(crate) async fn post_signup_password<St>(
    auth: AxumUserp<St>,
    Form(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): Form<PasswordIdNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.password_signup(&email, &password).await {
        Ok(auth) => {
            let next = crate::router::safe_next(next, &auth.routes.pages.post_login);
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
    auth: AxumUserp<St>,
    Form(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): Form<PasswordIdNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.password_login(&email, &password).await {
        Ok(auth) => {
            let next = crate::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            PasswordLoginError::StoreError(err) => Err(err),
            PasswordLoginError::NotAllowed | PasswordLoginError::WrongPassword => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

use axum::extract::Query;
use axum::http::StatusCode;
use axum::{
    response::{IntoResponse, Redirect},
    Form,
};
use serde::{Deserialize, Serialize};
use crate::{
    axum::AxumAuthery,
    email::{
        login::{EmailLoginCallbackError, EmailLoginError, EmailLoginInitError},
        signup::{EmailSignupCallbackError, EmailSignupInitError},
        verify::{EmailVerifyCallbackError, EmailVerifyInitError},
        SendEmailChallengeError,
    },
    store::AutheryStore,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailNextForm {
    pub email: String,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeQuery {
    pub code: String,
}

#[derive(Deserialize)]
pub struct NewPasswordForm {
    pub new_password: String,
}

pub(crate) async fn post_login_email<St>(
    auth: AxumAuthery<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.email_login_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "{login_route}?message=Login link sent to {}!",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            EmailLoginInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
            _ => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

pub(crate) async fn get_login_email<St>(
    auth: AxumAuthery<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.email_login_callback(code).await {
        Ok((auth, next)) => {
            let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailLoginCallbackError::Store(err) => Err(err),
            EmailLoginCallbackError::EmailLoginError(EmailLoginError::Store(err)) => Err(err),
            _ => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

pub(crate) async fn post_signup_email<St>(
    auth: AxumAuthery<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.email_signup_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "{signup_route}?message=Signup email sent to {}!",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            EmailSignupInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
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

pub(crate) async fn get_signup_email<St>(
    auth: AxumAuthery<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.email_signup_callback(code).await {
        Ok((auth, next)) => {
            let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailSignupCallbackError::Store(err) => Err(err),
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

pub(crate) async fn get_user_email_verify<St>(
    auth: AxumAuthery<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    #[cfg(feature = "user")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "user"))]
    let user_route = auth.routes.pages.post_login.clone();

    match auth.email_verify_callback(code).await {
        Ok((address, next)) => {
            let next = match next {
                Some(next) => crate::axum::router::safe_next(Some(next), &login_route),
                None => {
                    if auth.logged_in().await? {
                        format!(
                            "{user_route}?message={} verified!",
                            urlencoding::encode(&address)
                        )
                    } else {
                        format!(
                            "{login_route}?message={} verified!",
                            urlencoding::encode(&address)
                        )
                    }
                }
            };

            Ok(Redirect::to(&next))
        }
        Err(err) => match err {
            EmailVerifyCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next))
            }
        },
    }
}

pub(crate) async fn post_user_email_verify<St>(
    auth: AxumAuthery<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    #[cfg(feature = "user")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "user"))]
    let user_route = auth.routes.pages.post_login.clone();

    match auth.email_verify_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "{user_route}?message=Verification mail sent to {}",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            EmailVerifyInitError::Store(err)
            | EmailVerifyInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
            _ => {
                let next = format!(
                    "{user_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

#[cfg(feature = "password")]
pub(crate) async fn post_password_send_reset<St>(
    auth: AxumAuthery<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let password_send_reset_route = auth.routes.pages.password_send_reset.clone();

    if let Err(err) = auth.email_reset_init(email.clone(), next).await {
        let next = format!(
            "{password_send_reset_route}?error={}&address={}",
            urlencoding::encode(&err.to_string()),
            urlencoding::encode(&email)
        );

        Ok(Redirect::to(&next).into_response())
    } else {
        let next = format!(
            "{password_send_reset_route}?sent=true&address={}",
            urlencoding::encode(&email)
        );

        Ok(Redirect::to(&next).into_response())
    }
}

#[cfg(feature = "password")]
pub async fn post_password_reset<St>(
    auth: AxumAuthery<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::models::{LoginSession, User};

    if let Some((user, session)) = auth.reset_user_session().await? {
        let new_password_hash = auth.pass.hasher.generate_hash(new_password).await;
        auth.store
            .set_user_password_hash(&user.get_id(), new_password_hash, &session.get_id())
            .await?;

        let login_route = auth.routes.pages.login.clone();

        // The reset session is single-use - drop it now that the password is set.
        let auth = auth.log_out().await?;

        Ok((
            auth,
            Redirect::to(&format!("{login_route}?message=Password has been reset")),
        )
            .into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

#[cfg(feature = "password")]
pub(crate) async fn get_password_reset_callback<St>(
    auth: AxumAuthery<St>,
    Query(query): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::email::reset::{EmailResetCallbackError, EmailResetError};

    let login_route = auth.routes.pages.login.clone();

    match auth.email_reset_callback(query.code).await {
        Ok(auth) => {
            let reset_password_page_route = auth.routes.pages.password_reset.clone();

            Ok((auth, Redirect::to(&reset_password_page_route)).into_response())
        }
        Err(err) => match err {
            EmailResetCallbackError::Store(err) => Err(err),
            EmailResetCallbackError::EmailResetError(EmailResetError::Store(err)) => Err(err),
            _ => Ok(Redirect::to(&format!(
                "{login_route}?err={}",
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        },
    }
}

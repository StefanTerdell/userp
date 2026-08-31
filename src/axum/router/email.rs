use crate::{
    axum::AxumAuthery,
    email::{
        SendEmailChallengeError,
        login::{EmailLoginCallbackError, EmailLoginError, EmailLoginInitError},
        signup::{EmailSignupCallbackError, EmailSignupInitError},
        verify::{EmailVerifyCallbackError, EmailVerifyInitError},
    },
    store::AutheryStore,
};
use axum::extract::Query;
use axum::http::StatusCode;
use axum::{
    Form,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};

/// The "check your inbox" page for a link that was just sent.
fn email_sent_url(
    routes: &crate::routes::Routes<String>,
    purpose: &str,
    address: &str,
    next: Option<&str>,
) -> String {
    let mut url = format!(
        "{}?purpose={purpose}&address={}&message={}",
        routes.pages.email_sent,
        urlencoding::encode(address),
        urlencoding::encode("Link sent")
    );
    if let Some(next) = next {
        url.push_str(&format!("&next={}", urlencoding::encode(next)));
    }
    url
}

/// The "link expired" page, carrying `error` so JSON clients get a 422.
fn email_expired_url(
    routes: &crate::routes::Routes<String>,
    purpose: &str,
    address: &str,
) -> String {
    format!(
        "{}?purpose={purpose}&address={}&error={}",
        routes.pages.email_expired,
        urlencoding::encode(address),
        urlencoding::encode("Link expired")
    )
}

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
    let routes = auth.routes.clone();

    match auth.email_login_init(email.clone(), next.clone()).await {
        Ok(()) => Ok(
            Redirect::to(&email_sent_url(&routes, "login", &email, next.as_deref()))
                .into_response(),
        ),
        Err(err) => match err {
            EmailLoginInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
            _ => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &crate::axum::router::with_method(&routes.pages.login, "email"),
                next.as_deref(),
            ))
            .into_response()),
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
    let routes = auth.routes.clone();

    match auth.email_login_callback(code).await {
        Ok((auth, next)) => {
            #[cfg(feature = "mfa")]
            if auth.mfa_pending_session().await?.is_some() {
                let url = crate::axum::router::mfa::mfa_redirect_url(&auth.routes, next.as_deref());
                return Ok((auth, Redirect::to(&url)).into_response());
            }

            let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailLoginCallbackError::Store(err) => Err(err),
            EmailLoginCallbackError::EmailLoginError(EmailLoginError::Store(err)) => Err(err),
            EmailLoginCallbackError::ChallengeExpired { address } => {
                Ok(Redirect::to(&email_expired_url(&routes, "login", &address)).into_response())
            }
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
    let routes = auth.routes.clone();

    match auth.email_signup_init(email.clone(), next.clone()).await {
        Ok(()) => Ok(
            Redirect::to(&email_sent_url(&routes, "signup", &email, next.as_deref()))
                .into_response(),
        ),
        Err(err) => match err {
            EmailSignupInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
            _ => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &routes,
                &err,
                &crate::axum::router::with_method(&routes.pages.signup, "email"),
                next.as_deref(),
            ))
            .into_response()),
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
    let routes = auth.routes.clone();

    match auth.email_signup_callback(code).await {
        Ok((auth, next)) => {
            #[cfg(feature = "mfa")]
            if auth.mfa_pending_session().await?.is_some() {
                let url = crate::axum::router::mfa::mfa_redirect_url(&auth.routes, next.as_deref());
                return Ok((auth, Redirect::to(&url)).into_response());
            }

            let next = crate::axum::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailSignupCallbackError::Store(err) => Err(err),
            EmailSignupCallbackError::ChallengeExpired { address } => {
                Ok(Redirect::to(&email_expired_url(&routes, "signup", &address)).into_response())
            }
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
            EmailVerifyCallbackError::ChallengeExpired { address } => Ok(Redirect::to(
                &email_expired_url(&auth.routes, "verify", &address),
            )),
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
            _ => Ok(Redirect::to(&crate::axum::router::error_redirect(
                &auth.routes,
                &err,
                &user_route,
                None,
            ))
            .into_response()),
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

    let routes = auth.routes.clone();

    if let Err(err) = auth.email_reset_init(email.clone(), next).await {
        let fallback = format!(
            "{password_send_reset_route}?address={}",
            urlencoding::encode(&email)
        );
        let next = crate::axum::router::error_redirect(&routes, &err, &fallback, None);

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
        let new_password_hash = match auth.new_password_hash(&new_password).await {
            Ok(hash) => hash,
            Err(err) => {
                return Ok(Redirect::to(&format!(
                    "{}?error={}",
                    auth.routes.pages.password_reset,
                    urlencoding::encode(&err.to_string())
                ))
                .into_response());
            }
        };
        auth.store
            .set_user_password_hash(&user.get_id(), new_password_hash, &session.get_id())
            .await?;

        let login_route = auth.routes.pages.login.clone();

        // A reset means the old credential may be compromised: end every
        // session, the single-use reset session included.
        let auth = auth.log_out_everywhere().await?;

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

    let routes = auth.routes.clone();

    let login_route = auth.routes.pages.login.clone();

    match auth.email_reset_callback(query.code).await {
        Ok(auth) => {
            let reset_password_page_route = auth.routes.pages.password_reset.clone();

            Ok((auth, Redirect::to(&reset_password_page_route)).into_response())
        }
        Err(err) => match err {
            EmailResetCallbackError::Store(err) => Err(err),
            EmailResetCallbackError::EmailResetError(EmailResetError::Store(err)) => Err(err),
            EmailResetCallbackError::ChallengeExpired { address } => {
                Ok(Redirect::to(&email_expired_url(&routes, "reset", &address)).into_response())
            }
            _ => Ok(Redirect::to(&format!(
                "{login_route}?err={}",
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        },
    }
}

use axum::extract::Query;
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;
use crate::pages::{LoginTemplate, SignupTemplate};
use crate::{axum::AxumAuthery, store::AutheryStore};

#[derive(Deserialize)]
pub struct NextMessageErrorQuery {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct AddressMessageSentErrorQuery {
    pub address: Option<String>,
    pub message: Option<String>,
    pub sent: Option<bool>,
    pub error: Option<String>,
}

pub async fn get_login<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        Redirect::to(&auth.routes.pages.post_login).into_response()
    } else {
        let view = LoginTemplate::with(&auth, next.as_deref(), message.as_deref(), error.as_deref());
        Html(auth.pages.render_login(&view)).into_response()
    })
}

pub async fn get_signup<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery {
        error,
        message,
        next,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let view = SignupTemplate::with(&auth, next.as_deref(), message.as_deref(), error.as_deref());
    Ok(Html(auth.pages.render_signup(&view)).into_response())
}

#[cfg(feature = "user")]
pub async fn get_user<St>(
    auth: AxumAuthery<St>,
    Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::UserTemplate;
    use crate::models::User;

    let login_route = auth.routes.pages.login.clone();

    Ok(if let Some((user, session)) = auth.user_session().await? {
        let sessions = auth.store.get_user_sessions(&user.get_id()).await?;
        #[cfg(feature = "email")]
        let emails = auth.store.get_user_emails(&user.get_id()).await?;
        #[cfg(feature = "oauth")]
        let oauth_tokens = auth.store.get_user_oauth_tokens(&user.get_id()).await?;

        let view = UserTemplate::with(
            &auth,
            &user,
            &session,
            &sessions,
            message.as_deref(),
            error.as_deref(),
            #[cfg(feature = "email")]
            &emails,
            #[cfg(feature = "oauth")]
            &oauth_tokens,
        );
        Html(auth.pages.render_user(&view)).into_response()
    } else {
        Redirect::to(&format!("{login_route}?next=%2Fuser")).into_response()
    })
}

#[cfg(all(feature = "password", feature = "email"))]
pub async fn get_password_send_reset<St>(
    auth: AxumAuthery<St>,
    Query(query): Query<AddressMessageSentErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::pages::SendResetPasswordTemplate;

    let view = SendResetPasswordTemplate {
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address.as_deref(),
        error: query.error.as_deref(),
        message: query.message.as_deref(),
        send_reset_password_action_route: &auth.routes.email.password_send_reset,
    };
    Ok(Html(auth.pages.render_send_reset_password(&view)))
}

#[cfg(all(feature = "email", feature = "password"))]
pub async fn get_password_reset<St>(auth: AxumAuthery<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use axum::http::StatusCode;
    use crate::pages::ResetPasswordTemplate;

    if auth.is_reset_session().await? {
        let view = ResetPasswordTemplate {
            reset_password_action_route: &auth.routes.email.password_reset,
        };
        Ok(Html(auth.pages.render_reset_password(&view)).into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

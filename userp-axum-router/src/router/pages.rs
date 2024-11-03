use axum::extract::Query;
use axum::{
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use userp_pages::{LoginTemplate, SignupTemplate};
use userp_server::{axum::AxumUserp, store::UserpStore};

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
    auth: AxumUserp<St>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        Redirect::to(&auth.routes.pages.post_login).into_response()
    } else {
        LoginTemplate::into_response_with(
            &auth,
            next.as_deref(),
            message.as_deref(),
            error.as_deref(),
        )
        .into_response()
    })
}

pub async fn get_signup<St>(
    auth: AxumUserp<St>,
    Query(NextMessageErrorQuery {
        error,
        message,
        next,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(
        SignupTemplate::response_from(&auth, next.as_deref(), message.as_deref(), error.as_deref())
            .into_response(),
    )
}

#[cfg(feature = "account")]
pub async fn get_user<St>(
    auth: AxumUserp<St>,
    Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use userp_pages::UserTemplate;
    use userp_server::models::User;

    let login_route = auth.routes.pages.login.clone();

    Ok(if let Some((user, session)) = auth.user_session().await? {
        let sessions = auth.store.get_user_sessions(user.get_id()).await?;
        #[cfg(feature = "email")]
        let emails = auth.store.get_user_emails(user.get_id()).await?;
        #[cfg(feature = "oauth-callbacks")]
        let oauth_tokens = auth.store.get_user_oauth_tokens(user.get_id()).await?;

        UserTemplate::into_response_with(
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
        )
        .into_response()
    } else {
        Redirect::to(&format!("{login_route}?next=%2Fuser")).into_response()
    })
}

#[cfg(all(feature = "password", feature = "email"))]
pub async fn get_password_send_reset<St>(
    auth: AxumUserp<St>,
    Query(query): Query<AddressMessageSentErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use userp_pages::SendResetPasswordTemplate;

    Ok(SendResetPasswordTemplate {
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address.as_deref(),
        error: query.error.as_deref(),
        message: query.message.as_deref(),
        send_reset_password_action_route: &auth.routes.email.password_send_reset,
    }
    .into_response())
}

#[cfg(all(feature = "email", feature = "password"))]
pub async fn get_password_reset<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use axum::http::StatusCode;
    use userp_pages::ResetPasswordTemplate;

    if auth.is_reset_session().await? {
        Ok(ResetPasswordTemplate {
            reset_password_action_route: &auth.routes.email.password_reset,
        }
        .into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

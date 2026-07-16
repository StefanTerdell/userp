use crate::{
    axum::AxumAuthery,
    models::{LoginSession, User},
    store::AutheryStore,
};
use axum::response::IntoResponse;
use axum::{Form, http::StatusCode, response::Redirect};
use serde::Deserialize;
use urlencoding::encode;

#[cfg(feature = "email")]
use crate::models::email::UserEmail;

#[derive(Deserialize)]
pub struct IdAccountForm {
    /// An entity ID in its string representation
    pub id: String,
}

#[derive(Deserialize)]
pub struct NewPasswordAccountForm {
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct EmailAccountForm {
    pub email: String,
}

pub async fn post_user_delete<St>(auth: AxumAuthery<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    Ok(if let Some(user) = auth.user().await? {
        let signup_route = auth.routes.pages.signup.clone();

        auth.store.delete_user(&user.get_id()).await?;

        (auth.log_out().await?, Redirect::to(&signup_route)).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    })
}

#[cfg(feature = "password")]
pub async fn post_user_password_set<St>(
    auth: AxumAuthery<St>,
    Form(NewPasswordAccountForm { new_password }): Form<NewPasswordAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let mut user_session = auth.user_session().await?;
    let mut is_reset_session = false;

    #[cfg(all(feature = "password", feature = "email"))]
    if user_session.is_none() {
        user_session = auth.reset_user_session().await?;
        is_reset_session = user_session.is_some();
    }

    let Some((user, session)) = user_session else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let new_password_hash = auth.pass.hasher.generate_hash(new_password).await;

    auth.store
        .set_user_password_hash(&user.get_id(), new_password_hash, &session.get_id())
        .await?;

    let user_route = auth.routes.pages.user.clone();

    // A reset session is single-use - drop it once the password is set.
    if is_reset_session {
        let login_route = auth.routes.pages.login.clone();
        let auth = auth.log_out().await?;

        return Ok((
            auth,
            Redirect::to(&format!("{login_route}?message=The password has been set!")),
        )
            .into_response());
    }

    Ok(Redirect::to(&format!("{user_route}?message=The password has been set!")).into_response())
}

#[cfg(feature = "password")]
pub async fn post_user_password_delete<St>(
    auth: AxumAuthery<St>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some((user, session)) = auth.user_session().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .clear_user_password_hash(&user.get_id(), &session.get_id())
        .await?;

    let user_route = auth.routes.pages.user.clone();

    Ok((
        auth,
        Redirect::to(&format!("{user_route}?message=Password cleared")),
    )
        .into_response())
}

#[cfg(feature = "oauth")]
pub async fn post_user_oauth_delete<St>(
    auth: AxumAuthery<St>,
    Form(IdAccountForm { id }): Form<IdAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let Ok(id) = id.parse::<St::OAuthTokenId>() else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };

    auth.store.delete_oauth_token(&user.get_id(), &id).await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Token deleted")).into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_add<St>(
    auth: AxumAuthery<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.add_user_email(&user.get_id(), email).await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Email added")).into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_delete<St>(
    auth: AxumAuthery<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_user_email(&user.get_id(), email).await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Email deleted")).into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_enable_login<St>(
    auth: AxumAuthery<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let user_route = auth.routes.pages.user.clone();

    // Only verified addresses may be used for link login - otherwise the
    // owner of an unverified address could be logged into this account.
    let verified = auth
        .store
        .get_user_emails(&user.get_id())
        .await?
        .iter()
        .any(|e| e.get_address() == email && e.get_verified());

    if !verified {
        return Ok(Redirect::to(&format!(
            "{user_route}?error={}",
            encode("The address must be verified first")
        ))
        .into_response());
    }

    auth.store
        .set_user_email_allow_link_login(&user.get_id(), email.clone(), true)
        .await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!(
        "{user_route}?message={}",
        encode(&format!("You can now log in directly with {email}"))
    ))
    .into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_disable_login<St>(
    auth: AxumAuthery<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .set_user_email_allow_link_login(&user.get_id(), email.clone(), false)
        .await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!(
        "{user_route}?message={}",
        encode(&format!("You can no longer log in directly with {email}"))
    ))
    .into_response())
}

pub async fn post_user_session_delete<St>(
    auth: AxumAuthery<St>,
    Form(IdAccountForm { id }): Form<IdAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let Ok(id) = id.parse::<St::SessionId>() else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };

    auth.store.delete_session(&user.get_id(), &id).await?;

    #[cfg(feature = "pages")]
    let user_route = auth.routes.pages.user;
    #[cfg(not(feature = "pages"))]
    let user_route = auth.routes.pages.post_login;

    Ok(Redirect::to(&format!("{user_route}?message=Session deleted")).into_response())
}

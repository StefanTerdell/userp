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

#[cfg(all(feature = "totp", feature = "pages"))]
pub(crate) use totp_handlers::post_user_totp_enroll;
#[cfg(feature = "totp")]
pub(crate) use totp_handlers::{post_user_totp_confirm, post_user_totp_disable};

#[cfg(feature = "totp")]
mod totp_handlers {
    use super::*;
    use crate::models::User;
    use crate::models::email::UserEmail;
    use crate::totp::TotpError;
    use axum::Form;
    use serde::Deserialize;

    /// Begin enrollment and render the QR/confirm page directly - the QR
    /// payload is too large to survive a redirect.
    #[cfg(feature = "pages")]
    pub(crate) async fn post_user_totp_enroll<St>(
        auth: AxumAuthery<St>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        use crate::pages::TotpEnrollTemplate;
        use axum::response::Html;

        let login_route = auth.routes.pages.login.clone();

        // The authenticator shows this label under the issuer; prefer the
        // user's email when there is one.
        let account_label = match auth.user().await? {
            Some(user) => {
                #[cfg(feature = "email")]
                {
                    auth.store
                        .get_user_emails(&user.get_id())
                        .await?
                        .first()
                        .map(|e| e.get_address().to_string())
                        .unwrap_or_else(|| user.get_id().to_string())
                }
                #[cfg(not(feature = "email"))]
                {
                    user.get_id().to_string()
                }
            }
            None => return Ok(Redirect::to(&login_route).into_response()),
        };

        match auth.totp_enroll_start(&account_label).await {
            Ok(enrollment) => {
                let view = TotpEnrollTemplate {
                    qr_png_base64: &enrollment.qr_png_base64,
                    otpauth_url: &enrollment.otpauth_url,
                    secret: &enrollment.secret,
                    confirm_action_route: &auth.routes.user.user_totp_confirm,
                    user_page_route: &auth.routes.pages.user,
                    error: None,
                };
                Ok(Html(auth.pages.render_totp_enroll(&view)).into_response())
            }
            Err(TotpError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&format!(
                "{}?error={}",
                auth.routes.pages.user,
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        }
    }

    #[derive(Deserialize)]
    pub struct TotpCodeForm {
        pub code: String,
    }

    pub(crate) async fn post_user_totp_confirm<St>(
        auth: AxumAuthery<St>,
        Form(TotpCodeForm { code }): Form<TotpCodeForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let user_route = auth.routes.pages.user.clone();

        match auth.totp_enroll_confirm(&code).await {
            Ok(()) => Ok(
                Redirect::to(&format!("{user_route}?message=Authenticator app enabled"))
                    .into_response(),
            ),
            Err(TotpError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&format!(
                "{user_route}?error={}",
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        }
    }

    pub(crate) async fn post_user_totp_disable<St>(
        auth: AxumAuthery<St>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let user_route = auth.routes.pages.user.clone();

        match auth.totp_disable().await {
            Ok(()) => Ok(
                Redirect::to(&format!("{user_route}?message=Authenticator app disabled"))
                    .into_response(),
            ),
            Err(TotpError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&format!(
                "{user_route}?error={}",
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        }
    }
}

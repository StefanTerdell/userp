use crate::{
    axum::AxumAuthery,
    models::{User, oauth::OAuthToken},
    oauth::{
        OAuthGenericCallbackError, RefreshInitResult,
        link::{OAuthLinkCallbackError, OAuthLinkInitError},
        login::OAuthLoginCallbackError,
        refresh::OAuthRefreshCallbackError,
        signup::OAuthSignupCallbackError,
    },
    reexports::oauth2::{AuthorizationCode, CsrfToken},
    store::AutheryStore,
};
use axum::{
    Form,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct IdForm {
    /// An entity ID in its string representation
    pub id: String,
}
#[derive(Serialize, Deserialize)]
pub struct ProviderNextForm {
    pub provider: String,
    pub next: Option<String>,
}

#[derive(Deserialize)]
pub struct CodeStateQuery {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}

pub async fn post_user_oauth_refresh<St>(
    auth: AxumAuthery<St>,
    Form(IdForm { id: token_id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let Ok(token_id) = token_id.parse::<St::OAuthTokenId>() else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };

    let token = match auth.store.get_oauth_token_by_id(&token_id).await {
        Ok(Some(token)) if token.get_user_id() == user.get_id() => token,
        Ok(_) => {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        Err(err) => {
            eprintln!("{err:#?}");
            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    #[cfg(feature = "user")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "user"))]
    let user_route = auth.routes.pages.post_login.clone();

    Ok(
        match auth
            .oauth_refresh_init(
                token,
                Some(format!("{user_route}?message=Token refreshed").to_string()),
            )
            .await
        {
            Ok((auth, result)) => match result {
                RefreshInitResult::Ok => (
                    auth,
                    Redirect::to(&format!("{user_route}?message=Token refreshed")),
                )
                    .into_response(),
                RefreshInitResult::Redirect(redirect_url) => {
                    (auth, Redirect::to(redirect_url.as_str())).into_response()
                }
            },
            Err(err) => {
                let next = format!(
                    "{user_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Redirect::to(&next).into_response()
            }
        },
    )
}

/// The single OAuth callback: the flow type and provider ride the encrypted
/// state cookie, so this dispatches login/signup/link/refresh on its own.
pub async fn get_oauth<St>(
    auth: AxumAuthery<St>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();
    let signup_route = auth.routes.pages.signup.clone();
    #[cfg(feature = "user")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "user"))]
    let user_route = auth.routes.pages.post_login.clone();

    match auth.oauth_callback(code, state).await {
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
            OAuthGenericCallbackError::Signup(OAuthSignupCallbackError::Store(err))
            | OAuthGenericCallbackError::Login(OAuthLoginCallbackError::Store(err))
            | OAuthGenericCallbackError::Refresh(OAuthRefreshCallbackError::Store(err))
            | OAuthGenericCallbackError::Link(OAuthLinkCallbackError::Store(err)) => Err(err),
            // Errors land back on the page the flow started from.
            err => {
                let target = match &err {
                    OAuthGenericCallbackError::Signup(_) => &signup_route,
                    OAuthGenericCallbackError::Link(_) | OAuthGenericCallbackError::Refresh(_) => {
                        &user_route
                    }
                    _ => &login_route,
                };
                let next = format!("{target}?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

pub async fn post_user_oauth_link<St>(
    auth: AxumAuthery<St>,
    Form(ProviderNextForm { provider, next, .. }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    #[cfg(feature = "user")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "user"))]
    let user_route = auth.routes.pages.post_login.clone();

    match auth.oauth_link_init(provider, next).await {
        Ok((auth, redirect_url)) => Ok((auth, Redirect::to(redirect_url.as_str())).into_response()),
        Err(err) => match err {
            OAuthLinkInitError::Store(err) => Err(err),
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

pub async fn post_login_oauth<St>(
    auth: AxumAuthery<St>,
    Form(form): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.oauth_login_init(form.provider, form.next).await {
        Ok((auth, redirect_url)) => Ok((auth, Redirect::to(redirect_url.as_str())).into_response()),
        Err(err) => {
            let next = format!(
                "{login_route}?error={}",
                urlencoding::encode(&err.to_string())
            );
            Ok(Redirect::to(&next).into_response())
        }
    }
}

pub async fn post_signup_oauth<St>(
    auth: AxumAuthery<St>,
    Form(ProviderNextForm { provider, next, .. }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.oauth_signup_init(provider, next).await {
        Ok((auth, redirect_url)) => Ok((auth, Redirect::to(redirect_url.as_str())).into_response()),
        Err(err) => {
            let next = format!(
                "{signup_route}?error={}",
                urlencoding::encode(&err.to_string())
            );
            Ok(Redirect::to(&next).into_response())
        }
    }
}

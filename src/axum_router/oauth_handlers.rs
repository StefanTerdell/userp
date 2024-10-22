use crate::{
    oauth::{
        OAuthGenericCallbackError, OAuthLinkCallbackError, OAuthLinkInitError,
        OAuthLoginCallbackError, OAuthRefreshCallbackError, OAuthSignupCallbackError,
        RefreshInitResult,
    },
    Userp, UserpStore,
};
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Form,
};
use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

use super::{IdForm, ProviderNextForm};

#[derive(Deserialize)]
pub struct CodeStateQuery {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}

#[derive(Deserialize)]
pub struct ProviderPath {
    pub provider: String,
}

pub async fn get_login_oauth<St>(
    auth: Userp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();

    match auth.oauth_login_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or(auth.routes.post_login.to_string());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthLoginCallbackError::Store(err) => Err(err),
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

pub async fn get_user_oauth_refresh<St>(
    auth: Userp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let user_route = auth.routes.user.clone();

    match auth
        .oauth_refresh_callback(provider.clone(), code, state)
        .await
    {
        Ok(next) => {
            let next = next.unwrap_or(format!(
                "{user_route}?message={} token refreshed!",
                provider
            ));
            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            OAuthRefreshCallbackError::Store(err) => Err(err),
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

pub async fn post_user_oauth_refresh<St>(
    auth: Userp<St>,
    Form(IdForm { id: token_id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let token = match auth.store.oauth_get_token(token_id).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        Err(err) => {
            eprintln!("{err:#?}");
            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    let user_route = auth.routes.user.clone();

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

pub async fn get_generic_oauth<St>(
    auth: Userp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();

    match auth.oauth_generic_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or(auth.routes.post_login.clone());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthGenericCallbackError::Signup(OAuthSignupCallbackError::Store(err))
            | OAuthGenericCallbackError::Login(OAuthLoginCallbackError::Store(err))
            | OAuthGenericCallbackError::Refresh(OAuthRefreshCallbackError::Store(err))
            | OAuthGenericCallbackError::Link(OAuthLinkCallbackError::Store(err)) => Err(err),
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

pub async fn get_signup_oauth<St>(
    auth: Userp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.signup.clone();

    match auth.oauth_signup_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or(auth.routes.post_login.clone());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthSignupCallbackError::Store(err) => Err(err),
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

pub async fn post_user_oauth_link<St>(
    auth: Userp<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    let user_route = auth.routes.user.clone();

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

pub async fn get_user_oauth_link<St>(
    auth: Userp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    match auth.oauth_link_callback(provider, code, state).await {
        Ok(next) => {
            let next = next.unwrap_or(auth.routes.post_login.clone());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthLinkCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!(
                    "{}?error={}",
                    auth.routes.signup,
                    urlencoding::encode(&err.to_string())
                );
                Ok((auth, Redirect::to(&next)).into_response())
            }
        },
    }
}

pub async fn post_login_oauth<St>(
    auth: Userp<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();

    match auth.oauth_login_init(provider, next).await {
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
    auth: Userp<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.signup.clone();

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

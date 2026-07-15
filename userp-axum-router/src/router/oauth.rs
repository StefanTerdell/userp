use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Form,
};
use serde::{Deserialize, Serialize};
use userp_server::{
    axum::AxumUserp,
    models::{oauth::OAuthToken, User},
    oauth::{
        link::{OAuthLinkCallbackError, OAuthLinkInitError},
        login::OAuthLoginCallbackError,
        refresh::OAuthRefreshCallbackError,
        signup::OAuthSignupCallbackError,
        OAuthGenericCallbackError, RefreshInitResult,
    },
    reexports::oauth2::{AuthorizationCode, CsrfToken},
    store::UserpStore,
};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct IdForm {
    pub id: Uuid,
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

#[derive(Deserialize)]
pub struct ProviderPath {
    pub provider: String,
}

pub async fn get_login_oauth<St>(
    auth: AxumUserp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.oauth_login_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = crate::router::safe_next(next, &auth.routes.pages.post_login);
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
    mut auth: AxumUserp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    #[cfg(feature = "account")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "account"))]
    let user_route = auth.routes.pages.post_login.clone();

    match auth
        .oauth_refresh_callback(provider.clone(), code, state)
        .await
    {
        Ok(next) => {
            let fallback = format!("{user_route}?message={} token refreshed!", provider);
            let next = crate::router::safe_next(next, &fallback);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthRefreshCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!(
                    "{user_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok((auth, Redirect::to(&next)).into_response())
            }
        },
    }
}

pub async fn post_user_oauth_refresh<St>(
    auth: AxumUserp<St>,
    Form(IdForm { id: token_id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let token = match auth.store.oauth_get_token_by_id(token_id).await {
        Ok(Some(token)) if token.get_user_id() == user.get_id() => token,
        Ok(_) => {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        Err(err) => {
            eprintln!("{err:#?}");
            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    #[cfg(feature = "account")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "account"))]
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

pub async fn get_generic_oauth<St>(
    auth: AxumUserp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.oauth_generic_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = crate::router::safe_next(next, &auth.routes.pages.post_login);
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
    auth: AxumUserp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.oauth_signup_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = crate::router::safe_next(next, &auth.routes.pages.post_login);
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
    auth: AxumUserp<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    #[cfg(feature = "account")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "account"))]
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

pub async fn get_user_oauth_link<St>(
    mut auth: AxumUserp<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    match auth.oauth_link_callback(provider, code, state).await {
        Ok(next) => {
            let next = crate::router::safe_next(next, &auth.routes.pages.post_login);
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthLinkCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!(
                    "{}?error={}",
                    auth.routes.pages.signup,
                    urlencoding::encode(&err.to_string())
                );
                Ok((auth, Redirect::to(&next)).into_response())
            }
        },
    }
}

pub async fn post_login_oauth<St>(
    auth: AxumUserp<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

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
    auth: AxumUserp<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
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

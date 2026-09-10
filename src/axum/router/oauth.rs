use crate::axum::extract::FormOrJson;
use crate::axum::response::{ApiError, MALFORMED_ID, NOT_LOGGED_IN, StoreFailure};
use crate::{
    axum::AxumAuthery,
    models::{User, oauth::OAuthToken},
    oauth::{
        OAuthGenericCallbackError, RefreshInitResult,
        link::{OAuthLinkCallbackError, OAuthLinkInitError},
        login::OAuthLoginCallbackError,
        refresh::{OAuthRefreshCallbackError, OAuthRefreshInitError},
        signup::OAuthSignupCallbackError,
    },
    reexports::oauth2::{AuthorizationCode, CsrfToken},
    store::AutheryStore,
};
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct IdForm {
    /// An entity ID in its string representation
    pub id: String,
}
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct ProviderNextForm {
    /// The name a provider was registered under.
    pub provider: String,
    /// Where to send the browser afterwards; must be a local path.
    pub next: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct CodeStateQuery {
    /// The authorization code the provider sent back.
    #[cfg_attr(feature = "openapi", schemars(with = "String"))]
    pub code: AuthorizationCode,
    /// The opaque state value, matched against the flow's state cookie.
    #[cfg_attr(feature = "openapi", schemars(with = "String"))]
    pub state: CsrfToken,
}

pub async fn post_user_oauth_refresh<St>(
    auth: AxumAuthery<St>,
    FormOrJson(IdForm { id: token_id }): FormOrJson<IdForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let Some(user) = auth.user().await? else {
        return Ok(ApiError::response(StatusCode::UNAUTHORIZED, NOT_LOGGED_IN));
    };

    let Ok(token_id) = token_id.parse::<St::OAuthTokenId>() else {
        return Ok(ApiError::response(StatusCode::BAD_REQUEST, MALFORMED_ID));
    };

    let token = match auth.store.get_oauth_token_by_id(&token_id).await? {
        Some(token) if token.get_user_id() == user.get_id() => token,
        _ => {
            return Ok(ApiError::response(
                StatusCode::NOT_FOUND,
                "No such OAuth token.",
            ));
        }
    };

    let user_route = crate::axum::router::user_page(&auth.routes).clone();

    match auth
        .oauth_refresh_init(
            token,
            Some(format!("{user_route}?message=Token refreshed").to_string()),
        )
        .await
    {
        Ok((auth, result)) => Ok(match result {
            RefreshInitResult::Ok => (
                auth,
                Redirect::to(&format!("{user_route}?message=Token refreshed")),
            )
                .into_response(),
            RefreshInitResult::Redirect(redirect_url) => {
                (auth, Redirect::to(redirect_url.as_str())).into_response()
            }
        }),
        // The store's own words never reach the redirect.
        Err(OAuthRefreshInitError::Store(err)) => Err(err.into()),
        Err(err) => {
            let next = format!(
                "{user_route}?error={}",
                urlencoding::encode(&err.to_string())
            );
            Ok(Redirect::to(&next).into_response())
        }
    }
}

/// The single OAuth callback: the flow type and provider ride the encrypted
/// state cookie, so this dispatches login/signup/link/refresh on its own.
pub async fn get_oauth<St>(
    auth: AxumAuthery<St>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let login_route = auth.routes.pages.login.clone();
    let signup_route = auth.routes.pages.signup.clone();
    let user_route = crate::axum::router::user_page(&auth.routes).clone();

    match auth.oauth_callback(code, state).await {
        Ok((auth, next)) => crate::axum::router::complete_login(auth, next).await,
        Err(err) => match err {
            OAuthGenericCallbackError::Signup(OAuthSignupCallbackError::Store(err))
            | OAuthGenericCallbackError::Login(OAuthLoginCallbackError::Store(err))
            | OAuthGenericCallbackError::Refresh(OAuthRefreshCallbackError::Store(err))
            | OAuthGenericCallbackError::Link(OAuthLinkCallbackError::Store(err)) => {
                Err(err.into())
            }
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
    FormOrJson(ProviderNextForm { provider, next, .. }): FormOrJson<ProviderNextForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    if !auth.logged_in().await? {
        return Ok(ApiError::response(StatusCode::UNAUTHORIZED, NOT_LOGGED_IN));
    }

    let user_route = crate::axum::router::user_page(&auth.routes).clone();

    match auth.oauth_link_init(provider, next).await {
        Ok((auth, redirect_url)) => Ok((auth, Redirect::to(redirect_url.as_str())).into_response()),
        Err(err) => match err {
            OAuthLinkInitError::Store(err) => Err(err.into()),
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
    FormOrJson(form): FormOrJson<ProviderNextForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
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
    FormOrJson(ProviderNextForm { provider, next, .. }): FormOrJson<ProviderNextForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
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

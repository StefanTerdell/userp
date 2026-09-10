use crate::axum::extract::{FormOrJson, WebauthnJson};
use crate::axum::response::{ApiError, FlowResult, StoreFailure};
use crate::{
    axum::AxumAuthery,
    store::AutheryStore,
    webauthn::{WebauthnLoginError, WebauthnRegisterError},
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

/// Begin a discoverable passkey login. Returns the JSON challenge to pass to
/// `navigator.credentials.get()`; the ceremony state lands in the cookie jar.
pub(crate) async fn post_login_webauthn_start<St>(
    mut auth: AxumAuthery<St>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    Ok(match auth.webauthn_login_start() {
        Ok(rcr) => (auth, Json(rcr)).into_response(),
        Err(err) => ApiError::response(StatusCode::BAD_REQUEST, &err),
    })
}

/// Complete the passkey login. On success the session cookie is set and the
/// client script navigates to `next`.
pub(crate) async fn post_login_webauthn_finish<St>(
    auth: AxumAuthery<St>,
    WebauthnJson(credential): WebauthnJson<PublicKeyCredential>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let post_login = auth.routes.pages.post_login.clone();

    match auth.webauthn_login_finish(&credential).await {
        Ok(auth) => Ok((
            auth,
            Json(FlowResult {
                next: post_login,
                message: None,
            }),
        )
            .into_response()),
        Err(WebauthnLoginError::Store(err)) => Err(err.into()),
        Err(err) => Ok(ApiError::response(StatusCode::UNAUTHORIZED, &err)),
    }
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub(crate) struct RegisterStartBody {
    /// Shown by the authenticator when picking a credential; typically the
    /// user's email or handle.
    pub display_name: String,
    /// Optional label for the account page.
    pub name: Option<String>,
}

/// Begin registering a passkey for the logged-in user.
pub(crate) async fn post_user_webauthn_register_start<St>(
    mut auth: AxumAuthery<St>,
    FormOrJson(body): FormOrJson<RegisterStartBody>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    match auth
        .webauthn_register_start(&body.display_name, body.name)
        .await
    {
        Ok(ccr) => Ok((auth, Json(ccr)).into_response()),
        Err(WebauthnRegisterError::Store(err)) => Err(err.into()),
        Err(err) => Ok(ApiError::response(StatusCode::BAD_REQUEST, &err)),
    }
}

/// Store the new passkey after a successful create() ceremony.
pub(crate) async fn post_user_webauthn_register_finish<St>(
    mut auth: AxumAuthery<St>,
    WebauthnJson(credential): WebauthnJson<RegisterPublicKeyCredential>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    // Captured before the ceremony call borrows `auth` mutably. The account
    // page is where the new passkey shows up; without `user` there is none.
    #[cfg(feature = "user")]
    let next = auth.routes.pages.user.clone();
    #[cfg(not(feature = "user"))]
    let next = auth.routes.pages.post_login.clone();

    match auth.webauthn_register_finish(&credential).await {
        Ok(()) => Ok((
            auth,
            Json(FlowResult {
                next,
                message: None,
            }),
        )
            .into_response()),
        Err(WebauthnRegisterError::Store(err)) => Err(err.into()),
        // A rejected credential is a 401, as on both sibling ceremonies.
        Err(err) => Ok(ApiError::response(StatusCode::UNAUTHORIZED, &err)),
    }
}

#[cfg(feature = "user")]
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub(crate) struct DeleteCredentialForm {
    /// Hex-encoded credential id, as rendered on the account page.
    pub credential_id: String,
}

#[cfg(feature = "user")]
pub(crate) async fn post_user_webauthn_delete<St>(
    auth: AxumAuthery<St>,
    FormOrJson(form): FormOrJson<DeleteCredentialForm>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    use crate::models::LoginSession;

    let user_page = auth.routes.pages.user.clone();
    let login_page = auth.routes.pages.login.clone();

    let Some(session) = auth.session().await? else {
        return Ok(Redirect::to(&login_page).into_response());
    };

    let Ok(credential_id) = hex_decode(&form.credential_id) else {
        return Ok(Redirect::to(&format!("{user_page}?error=Bad credential id")).into_response());
    };

    auth.store
        .delete_passkey(&session.get_user_id(), &credential_id)
        .await?;

    Ok(Redirect::to(&format!("{user_page}?message=Passkey deleted")).into_response())
}

#[cfg(feature = "user")]
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

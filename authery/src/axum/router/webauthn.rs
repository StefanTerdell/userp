use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use crate::{
    axum::AxumAuthery,
    store::AutheryStore,
    webauthn::{WebauthnLoginError, WebauthnRegisterError},
};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

/// Begin a discoverable passkey login. Returns the JSON challenge to pass to
/// `navigator.credentials.get()`; the ceremony state lands in the cookie jar.
pub(crate) async fn post_login_webauthn_start<St>(
    mut auth: AxumAuthery<St>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    Ok(match auth.webauthn_login_start() {
        Ok(rcr) => (auth, Json(rcr)).into_response(),
        Err(err) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": err.to_string()}))).into_response()
        }
    })
}

/// Complete the passkey login. On success the session cookie is set and the
/// client script navigates to `next`.
pub(crate) async fn post_login_webauthn_finish<St>(
    auth: AxumAuthery<St>,
    Json(credential): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let post_login = auth.routes.pages.post_login.clone();

    match auth.webauthn_login_finish(&credential).await {
        Ok(auth) => Ok((auth, Json(json!({"next": post_login}))).into_response()),
        Err(WebauthnLoginError::Store(err)) => Err(err),
        Err(err) => Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": err.to_string()})),
        )
            .into_response()),
    }
}

#[derive(Deserialize)]
pub(crate) struct RegisterStartBody {
    /// Shown by the authenticator when picking a credential; typically the
    /// user's email or handle.
    pub display_name: String,
}

/// Begin registering a passkey for the logged-in user.
pub(crate) async fn post_user_webauthn_register_start<St>(
    mut auth: AxumAuthery<St>,
    Json(body): Json<RegisterStartBody>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    match auth.webauthn_register_start(&body.display_name).await {
        Ok(ccr) => Ok((auth, Json(ccr)).into_response()),
        Err(WebauthnRegisterError::Store(err)) => Err(err),
        Err(err) => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": err.to_string()})),
        )
            .into_response()),
    }
}

/// Store the new passkey after a successful create() ceremony.
pub(crate) async fn post_user_webauthn_register_finish<St>(
    mut auth: AxumAuthery<St>,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    match auth.webauthn_register_finish(&credential).await {
        Ok(()) => Ok((auth, StatusCode::OK).into_response()),
        Err(WebauthnRegisterError::Store(err)) => Err(err),
        Err(err) => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": err.to_string()})),
        )
            .into_response()),
    }
}

#[cfg(feature = "user")]
#[derive(Deserialize)]
pub(crate) struct DeleteCredentialForm {
    /// Hex-encoded credential id, as rendered on the account page.
    pub credential_id: String,
}

#[cfg(feature = "user")]
pub(crate) async fn post_user_webauthn_delete<St>(
    auth: AxumAuthery<St>,
    axum::Form(form): axum::Form<DeleteCredentialForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
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
        .webauthn_delete_credential(&session.get_user_id(), &credential_id)
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

#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "email")]
pub mod otp;
#[cfg(feature = "pages")]
pub mod pages;
#[cfg(feature = "password")]
pub mod password;
#[cfg(feature = "sms")]
pub mod sms;
#[cfg(feature = "user")]
pub mod user;
#[cfg(feature = "webauthn")]
pub mod webauthn;

use crate::axum::cookies::SharedCookieJar;
use crate::routes::Routes;
use crate::{Authery as AxumAuthery, config::AutheryConfig, store::AutheryStore};
use axum::{
    Router,
    extract::{FromRef, Request},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use std::sync::{Arc, Mutex};

/// Wraps `router` with middleware that builds the encrypted cookie jar once per
/// request, shares it with the handler via request extensions, and serializes it
/// onto the response afterwards. With this applied, handlers no longer need to
/// return the auth service to persist session cookies. The built-in
/// [`AxumRouter::router`] applies it automatically; call this yourself when
/// wiring authery handlers into a hand-rolled router.
///
/// With `expose_auth_token` (the [`crate::config::AutheryConfig::bearer_auth`]
/// setting), a request that establishes a NEW session also gets an
/// `X-Auth-Token` response header carrying the session id — prefixed with
/// `auth_token_prefix` when one is configured — so non-browser clients can
/// capture it and authenticate with `Authorization: Bearer {token}` from
/// then on.
pub fn with_cookie_layer<S>(
    router: Router<S>,
    key: Key,
    expose_auth_token: bool,
    auth_token_prefix: Option<String>,
    previous_keys: Vec<Key>,
    session_cookie_name: String,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let previous_keys = Arc::new(previous_keys);
    let session_cookie_name = Arc::new(session_cookie_name);
    router.layer(from_fn(move |mut req: Request, next: Next| {
        let key = key.clone();
        let auth_token_prefix = auth_token_prefix.clone();
        let previous_keys = previous_keys.clone();
        let session_cookie_name = session_cookie_name.clone();
        async move {
            let jar = PrivateCookieJar::from_headers(req.headers(), key);
            let session_before = jar
                .get(session_cookie_name.as_str())
                .map(|c| c.value().to_string());
            let fallbacks: Vec<PrivateCookieJar> = previous_keys
                .iter()
                .map(|key| PrivateCookieJar::from_headers(req.headers(), key.clone()))
                .collect();
            let shared = SharedCookieJar {
                jar: Arc::new(Mutex::new(jar)),
                fallbacks: Arc::new(fallbacks),
            };
            req.extensions_mut().insert(shared.clone());

            let wants_json = wants_json(req.headers());

            let res = next.run(req).await;

            let jar = shared.jar.lock().unwrap().clone();
            let session_after = jar
                .get(session_cookie_name.as_str())
                .map(|c| c.value().to_string());

            let mut res = (jar, res).into_response();

            if expose_auth_token
                && session_after != session_before
                && let Some(token) = session_after
                && let Ok(value) = match &auth_token_prefix {
                    Some(prefix) => format!("{prefix}{token}").parse(),
                    None => token.parse(),
                }
            {
                res.headers_mut().insert("x-auth-token", value);
            }

            if wants_json {
                res = jsonify_redirect(res);
            }

            res
        }
    }))
}

/// `Accept: application/json` (without `text/html` outranking it) marks an
/// API client.
fn wants_json(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("application/json") && !accept.contains("text/html"))
}

/// The flows speak browser: outcomes are redirects, with errors and messages
/// riding `?error=`/`?message=` query params. For JSON clients the transport
/// layer translates that uniformly - EVERY flow redirect becomes:
///
/// - `200 {"next": "..."}` on success (with `"message"` when one rides along)
/// - `422 {"error": "...", "next": "..."}` when the redirect carries an error
///
/// Cookies and the `X-Auth-Token` header are preserved, so bearer clients
/// log in by POSTing the same forms with `Accept: application/json`.
fn jsonify_redirect(res: axum::response::Response) -> axum::response::Response {
    use axum::http::{StatusCode, header};

    if !res.status().is_redirection() {
        return res;
    }

    let Some(location) = res
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return res;
    };

    let mut error = None;
    let mut message = None;
    if let Some(query) = location.split_once('?').map(|(_, q)| q) {
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = || urlencoding::decode(v).unwrap_or_default().into_owned();
            match k {
                "error" => error = Some(v()),
                "message" => message = Some(v()),
                _ => {}
            }
        }
    }

    let mut body = serde_json::Map::new();
    body.insert("next".into(), location.clone().into());
    if let Some(message) = message {
        body.insert("message".into(), message.into());
    }
    let status = match &error {
        Some(error) => {
            body.insert("error".into(), error.clone().into());
            StatusCode::UNPROCESSABLE_ENTITY
        }
        None => StatusCode::OK,
    };

    let (mut parts, _) = res.into_parts();
    parts.status = status;
    parts.headers.remove(header::LOCATION);
    parts.headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);

    axum::response::Response::from_parts(
        parts,
        axum::body::Body::from(serde_json::Value::Object(body).to_string()),
    )
}

/// The paused page for a rate-limit refusal. Carries `error` so JSON clients
/// get a 422.
pub(crate) fn paused_url(
    routes: &Routes<String>,
    limited: &crate::ratelimit::RateLimited,
    next: Option<&str>,
) -> String {
    let mut url = format!(
        "{}?error={}",
        routes.pages.paused,
        urlencoding::encode("Too many attempts")
    );
    if let Some(retry_after) = limited.retry_after {
        url.push_str(&format!(
            "&retry_after={}",
            retry_after.num_seconds().max(1)
        ));
    }
    if let Some(next) = next {
        url.push_str(&format!("&next={}", urlencoding::encode(next)));
    }
    url
}

/// `fallback` with `error=` appended, or the paused page when the error is a
/// rate-limit refusal.
pub(crate) fn error_redirect(
    routes: &Routes<String>,
    err: &(impl std::fmt::Display + crate::ratelimit::MaybeRateLimited),
    fallback: &str,
    next: Option<&str>,
) -> String {
    if let Some(limited) = err.rate_limited() {
        return paused_url(routes, limited, next);
    }
    let separator = if fallback.contains('?') { '&' } else { '?' };
    format!(
        "{fallback}{separator}error={}",
        urlencoding::encode(&err.to_string())
    )
}

/// Whether `next` is a local path that is safe to redirect to.
pub(crate) fn is_safe_next(next: &str) -> bool {
    next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && !next.contains(|c: char| c.is_ascii_control())
}

/// Guards against open redirects: only local paths pass through,
/// anything absolute, protocol-relative or malformed becomes the fallback.
pub(crate) fn safe_next(next: Option<String>, fallback: &str) -> String {
    match next {
        Some(next) if is_safe_next(&next) => next,
        _ => fallback.to_string(),
    }
}

/// `page` with `method=` appended, so the page preselects that method's panel.
pub(crate) fn with_method(page: &str, method: &str) -> String {
    let separator = if page.contains('?') { '&' } else { '?' };
    format!("{page}{separator}method={method}")
}

/// The account page when the `user` feature is on, the post-login page
/// otherwise.
#[cfg(any(feature = "oauth", feature = "email", feature = "user"))]
pub(crate) fn user_page(routes: &Routes<String>) -> &String {
    #[cfg(feature = "user")]
    {
        &routes.pages.user
    }
    #[cfg(not(feature = "user"))]
    {
        &routes.pages.post_login
    }
}

/// Complete a fresh login: redirect to the MFA page when a second factor is
/// pending, else to the sanitized `next`.
#[cfg(any(
    feature = "email",
    feature = "sms",
    feature = "password",
    feature = "oauth"
))]
pub(crate) async fn complete_login<St>(
    auth: crate::axum::AxumAuthery<St>,
    next: Option<String>,
) -> Result<axum::response::Response, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    #[cfg(feature = "mfa")]
    if auth.mfa_pending_session().await?.is_some() {
        let url = mfa::mfa_redirect_url(&auth.routes, next.as_deref());
        return Ok((auth, Redirect::to(&url)).into_response());
    }

    let next = safe_next(next, &auth.routes.pages.post_login);
    Ok((auth, Redirect::to(&next)).into_response())
}

/// One code-flow POST step: without `code` it sends a code to the identifier,
/// with one it verifies it and completes the login. An empty `code` counts as
/// absent.
#[cfg(any(feature = "email", feature = "sms"))]
pub(crate) async fn post_code_flow<St, Ch>(
    auth: crate::axum::AxumAuthery<St>,
    identifier: String,
    code: Option<String>,
    next: Option<String>,
    intent: crate::models::Intent,
    action_route: String,
    method: &str,
) -> Result<axum::response::Response, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
    Ch: crate::code_flow::CodeLoginFlow,
{
    use crate::code_flow::{CodeInitError, CodeVerifyError};
    use crate::models::Intent;

    let routes = auth.routes.clone();
    let page = match intent {
        Intent::LogIn => &routes.pages.login,
        Intent::SignUp => &routes.pages.signup,
    };

    match code.filter(|code| !code.is_empty()) {
        None => match auth
            .code_init::<Ch>(identifier.clone(), next.clone(), intent)
            .await
        {
            Ok(()) => Ok(Redirect::to(&format!(
                "{action_route}?address={}&message=Code sent!",
                urlencoding::encode(&identifier)
            ))
            .into_response()),
            Err(CodeInitError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&error_redirect(
                &routes,
                &err,
                &with_method(page, method),
                next.as_deref(),
            ))
            .into_response()),
        },
        Some(code) => match auth.code_verify::<Ch>(&identifier, &code, intent).await {
            Ok((auth, next)) => complete_login(auth, next).await,
            Err(CodeVerifyError::Store(err)) => Err(err),
            Err(err) => Ok(Redirect::to(&error_redirect(
                &routes,
                &err,
                &format!(
                    "{action_route}?address={}",
                    urlencoding::encode(&identifier)
                ),
                next.as_deref(),
            ))
            .into_response()),
        },
    }
}

/// A `{ "error": … }` JSON body with the given status.
#[cfg(feature = "webauthn")]
pub(crate) fn json_error(
    status: StatusCode,
    err: &impl std::fmt::Display,
) -> axum::response::Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": err.to_string() })),
    )
        .into_response()
}

pub trait AxumRouter {
    fn routes(&self) -> &Routes;

    /// The cookie-encryption key, used to install the cookie-propagation layer.
    fn cookie_key(&self) -> Key;

    /// Whether bearer-token auth is enabled (exposes `X-Auth-Token` on fresh
    /// logins); see [`crate::config::AutheryConfig::bearer_auth`].
    fn bearer_auth(&self) -> bool {
        false
    }

    /// The wire prefix for bearer tokens, if any; see
    /// [`crate::config::AutheryConfig::bearer_token_prefix`].
    fn bearer_token_prefix(&self) -> Option<String> {
        None
    }

    /// Previous cookie keys accepted during rotation; see
    /// [`crate::config::AutheryConfig::previous_keys`].
    fn previous_cookie_keys(&self) -> Vec<Key> {
        Vec::new()
    }

    /// See [`crate::config::AutheryConfig::cookie_names`].
    fn cookie_names(&self) -> crate::cookie_names::CookieNames {
        Default::default()
    }

    fn router<St, S>(&self) -> Router<S>
    where
        AutheryConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AutheryStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        let mut router = Router::new();

        router = router
            .route(self.routes().logout.as_str(), post(post_user_logout::<St>))
            .route(
                self.routes().user_verify_session.as_str(),
                get(get_user_verify_session::<St>),
            );

        #[cfg(feature = "pages")]
        {
            router = router
                .route(
                    self.routes().pages.login.as_str(),
                    get(pages::get_login::<St>),
                )
                .route(
                    self.routes().pages.signup.as_str(),
                    get(pages::get_signup::<St>),
                )
                .route(
                    self.routes().pages.paused.as_str(),
                    get(pages::get_paused::<St>),
                );

            #[cfg(feature = "email")]
            {
                router = router
                    .route(
                        self.routes().pages.email_sent.as_str(),
                        get(pages::get_email_sent::<St>),
                    )
                    .route(
                        self.routes().pages.email_expired.as_str(),
                        get(pages::get_email_expired::<St>),
                    );
            }

            #[cfg(all(feature = "email", feature = "password"))]
            {
                router = router
                    .route(
                        self.routes().pages.password_send_reset.as_str(),
                        get(pages::get_password_send_reset::<St>),
                    )
                    .route(
                        self.routes().pages.password_reset.as_str(),
                        get(pages::get_password_reset::<St>),
                    );
            }

            #[cfg(feature = "user")]
            {
                router = router.route(
                    self.routes().pages.user.as_str(),
                    get(pages::get_user::<St>),
                );
            }
        }

        #[cfg(feature = "user")]
        {
            router = router
                .route(
                    self.routes().user.user_delete.as_str(),
                    post(user::post_user_delete::<St>),
                )
                .route(
                    self.routes().user.user_session_delete.as_str(),
                    post(user::post_user_session_delete::<St>),
                )
                .route(
                    self.routes().user.user_session_delete_others.as_str(),
                    post(user::post_user_session_delete_others::<St>),
                );

            #[cfg(feature = "password")]
            {
                router = router
                    .route(
                        self.routes().user.user_password_set.as_str(),
                        post(user::post_user_password_set::<St>),
                    )
                    .route(
                        self.routes().user.user_password_delete.as_str(),
                        post(user::post_user_password_delete::<St>),
                    );
            }

            #[cfg(feature = "oauth")]
            {
                router = router.route(
                    self.routes().user.user_oauth_delete.as_str(),
                    post(user::post_user_oauth_delete::<St>),
                );
            }

            #[cfg(feature = "totp")]
            {
                router = router
                    .route(
                        self.routes().user.user_totp_confirm.as_str(),
                        post(user::post_user_totp_confirm::<St>),
                    )
                    .route(
                        self.routes().user.user_totp_disable.as_str(),
                        post(user::post_user_totp_disable::<St>),
                    );

                #[cfg(feature = "pages")]
                {
                    router = router.route(
                        self.routes().user.user_totp_enroll.as_str(),
                        post(user::post_user_totp_enroll::<St>),
                    );
                }
            }

            #[cfg(all(feature = "mfa", feature = "pages"))]
            {
                router = router.route(
                    self.routes().user.user_recovery_codes.as_str(),
                    post(user::post_user_recovery_codes::<St>),
                );
            }

            #[cfg(feature = "email")]
            {
                router = router
                    .route(
                        self.routes().user.user_email_add.as_str(),
                        post(user::post_user_email_add::<St>),
                    )
                    .route(
                        self.routes().user.user_email_delete.as_str(),
                        post(user::post_user_email_delete::<St>),
                    )
                    .route(
                        self.routes().user.user_email_enable_login.as_str(),
                        post(user::post_user_email_enable_login::<St>),
                    )
                    .route(
                        self.routes().user.user_email_disable_login.as_str(),
                        post(user::post_user_email_disable_login::<St>),
                    );
            }
        }

        #[cfg(feature = "oauth")]
        {
            router = router
                .route(
                    self.routes().oauth.login_oauth.as_str(),
                    post(oauth::post_login_oauth::<St>),
                )
                .route(
                    self.routes().oauth.signup_oauth.as_str(),
                    post(oauth::post_signup_oauth::<St>),
                )
                .route(
                    self.routes().oauth.user_oauth_link.as_str(),
                    post(oauth::post_user_oauth_link::<St>),
                )
                .route(
                    self.routes().oauth.user_oauth_refresh.as_str(),
                    post(oauth::post_user_oauth_refresh::<St>),
                );

            router = router.route(
                self.routes().oauth.callback.as_str(),
                get(oauth::get_oauth::<St>),
            );
        }

        #[cfg(feature = "password")]
        {
            router = router
                .route(
                    self.routes().password.login_password.as_str(),
                    post(password::post_login_password::<St>),
                )
                .route(
                    self.routes().password.signup_password.as_str(),
                    post(password::post_signup_password::<St>),
                );
        }

        #[cfg(feature = "webauthn")]
        {
            router = router
                .route(
                    self.routes().webauthn.login_webauthn_start.as_str(),
                    post(webauthn::post_login_webauthn_start::<St>),
                )
                .route(
                    self.routes().webauthn.login_webauthn_finish.as_str(),
                    post(webauthn::post_login_webauthn_finish::<St>),
                )
                .route(
                    self.routes().webauthn.user_webauthn_register_start.as_str(),
                    post(webauthn::post_user_webauthn_register_start::<St>),
                )
                .route(
                    self.routes()
                        .webauthn
                        .user_webauthn_register_finish
                        .as_str(),
                    post(webauthn::post_user_webauthn_register_finish::<St>),
                );

            #[cfg(feature = "user")]
            {
                router = router.route(
                    self.routes().webauthn.user_webauthn_delete.as_str(),
                    post(webauthn::post_user_webauthn_delete::<St>),
                );
            }
        }

        #[cfg(feature = "mfa")]
        {
            #[cfg(feature = "pages")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa.as_str(),
                    get(pages::get_login_mfa::<St>),
                );
            }

            #[cfg(feature = "email")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa_otp.as_str(),
                    post(mfa::post_login_mfa_otp::<St>),
                );
            }

            #[cfg(feature = "totp")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa_totp.as_str(),
                    post(mfa::post_login_mfa_totp::<St>),
                );
            }

            #[cfg(feature = "sms")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa_sms.as_str(),
                    post(mfa::post_login_mfa_sms::<St>),
                );
            }

            router = router.route(
                self.routes().mfa.login_mfa_recovery.as_str(),
                post(mfa::post_login_mfa_recovery::<St>),
            );

            #[cfg(feature = "webauthn")]
            {
                router = router
                    .route(
                        self.routes().mfa.login_mfa_webauthn_start.as_str(),
                        post(mfa::post_login_mfa_webauthn_start::<St>),
                    )
                    .route(
                        self.routes().mfa.login_mfa_webauthn_finish.as_str(),
                        post(mfa::post_login_mfa_webauthn_finish::<St>),
                    );
            }
        }

        #[cfg(feature = "sms")]
        {
            let login_sms = post(sms::post_login_sms::<St>);
            let signup_sms = post(sms::post_signup_sms::<St>);

            #[cfg(feature = "pages")]
            let login_sms = login_sms.get(pages::get_login_sms::<St>);
            #[cfg(feature = "pages")]
            let signup_sms = signup_sms.get(pages::get_signup_sms::<St>);

            router = router
                .route(self.routes().sms.login_sms.as_str(), login_sms)
                .route(self.routes().sms.signup_sms.as_str(), signup_sms);
        }

        #[cfg(feature = "email")]
        {
            let login_otp = post(otp::post_login_otp::<St>);
            let signup_otp = post(otp::post_signup_otp::<St>);

            // With pages active, GET on the same paths renders the
            // code-entry form.
            #[cfg(feature = "pages")]
            let login_otp = login_otp.get(pages::get_login_otp::<St>);
            #[cfg(feature = "pages")]
            let signup_otp = signup_otp.get(pages::get_signup_otp::<St>);

            router = router
                .route(self.routes().email.login_otp.as_str(), login_otp)
                .route(self.routes().email.signup_otp.as_str(), signup_otp);
        }

        #[cfg(feature = "email")]
        {
            router = router
                .route(
                    self.routes().email.login_email.as_str(),
                    post(email::post_login_email::<St>).get(email::get_login_email::<St>),
                )
                .route(
                    self.routes().email.signup_email.as_str(),
                    post(email::post_signup_email::<St>).get(email::get_signup_email::<St>),
                )
                .route(
                    self.routes().email.user_email_verify.as_str(),
                    post(email::post_user_email_verify::<St>)
                        .get(email::get_user_email_verify::<St>),
                );

            #[cfg(feature = "password")]
            {
                router = router
                    .route(
                        self.routes().email.password_reset.as_str(),
                        post(email::post_password_reset::<St>),
                    )
                    .route(
                        self.routes().email.password_reset_callback.as_str(),
                        get(email::get_password_reset_callback::<St>),
                    )
                    .route(
                        self.routes().email.password_send_reset.as_str(),
                        post(email::post_password_send_reset::<St>),
                    );
            }
        }

        with_cookie_layer(
            router,
            self.cookie_key(),
            self.bearer_auth(),
            self.bearer_token_prefix(),
            self.previous_cookie_keys(),
            self.cookie_names().session_id,
        )
    }
}

impl AxumRouter for AutheryConfig {
    fn routes(&self) -> &Routes {
        &self.routes
    }

    fn cookie_key(&self) -> Key {
        Key::from(self.key.as_bytes())
    }

    fn bearer_auth(&self) -> bool {
        self.bearer_auth
    }

    fn bearer_token_prefix(&self) -> Option<String> {
        self.bearer_token_prefix.clone()
    }

    fn previous_cookie_keys(&self) -> Vec<Key> {
        self.previous_keys
            .iter()
            .map(|key| Key::from(key.as_bytes()))
            .collect()
    }

    fn cookie_names(&self) -> crate::cookie_names::CookieNames {
        self.cookie_names.clone()
    }
}

async fn post_user_logout<St>(auth: AxumAuthery<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let post_logout = auth.routes.pages.post_logout.clone();

    Ok((auth.log_out().await?, Redirect::to(&post_logout)))
}

async fn get_user_verify_session<St>(auth: AxumAuthery<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    })
}

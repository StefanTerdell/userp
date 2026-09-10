pub(crate) mod endpoint;

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
use crate::axum::response::{FlowError, FlowResult, StoreFailure, StoreFailureInfo};
use crate::routes::Routes;
use crate::{Authery as AxumAuthery, config::AutheryConfig, store::AutheryStore};
use axum::{
    Router,
    extract::{FromRef, Request},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use endpoint::Endpoint;
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
///
/// The layer also renders store failures for browsers: a handler's
/// [`crate::axum::response::StoreFailure`] leaves as a JSON body, and for a
/// client that did not ask for JSON the body is swapped for the error page
/// (`pages` and `login_page_route`, with the `pages` feature) or plain text.
#[allow(clippy::too_many_arguments)]
pub fn with_cookie_layer<S>(
    router: Router<S>,
    key: Key,
    expose_auth_token: bool,
    auth_token_prefix: Option<String>,
    previous_keys: Vec<Key>,
    session_cookie_name: String,
    #[cfg(feature = "pages")] pages: Arc<dyn crate::pages::Pages>,
    #[cfg(feature = "pages")] login_page_route: String,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    cookie_layered(
        router,
        key,
        expose_auth_token,
        auth_token_prefix,
        previous_keys,
        session_cookie_name,
        #[cfg(feature = "pages")]
        pages,
        #[cfg(feature = "pages")]
        login_page_route,
    )
}

/// A router the cookie layer can be applied to. Implemented for axum's
/// [`Router`] and, with the `aide` feature, for `aide::axum::ApiRouter`, so
/// the middleware body below is written once. The layer is a closure whose
/// type cannot be named, hence the callback shape.
pub(crate) trait CookieLayered: Sized {
    fn apply_cookie_layer<F, Fut>(self, middleware: F) -> Self
    where
        F: FnMut(Request, Next) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static;
}

impl<S> CookieLayered for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn apply_cookie_layer<F, Fut>(self, middleware: F) -> Self
    where
        F: FnMut(Request, Next) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        self.layer(from_fn(middleware))
    }
}

/// [`with_cookie_layer`], for any [`CookieLayered`] router.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cookie_layered<R: CookieLayered>(
    router: R,
    key: Key,
    expose_auth_token: bool,
    auth_token_prefix: Option<String>,
    previous_keys: Vec<Key>,
    session_cookie_name: String,
    #[cfg(feature = "pages")] pages: Arc<dyn crate::pages::Pages>,
    #[cfg(feature = "pages")] login_page_route: String,
) -> R {
    let previous_keys = Arc::new(previous_keys);
    let session_cookie_name = Arc::new(session_cookie_name);
    #[cfg(feature = "pages")]
    let login_page_route = Arc::new(login_page_route);
    router.apply_cookie_layer(move |mut req: Request, next: Next| {
        let key = key.clone();
        let auth_token_prefix = auth_token_prefix.clone();
        let previous_keys = previous_keys.clone();
        let session_cookie_name = session_cookie_name.clone();
        #[cfg(feature = "pages")]
        let pages = pages.clone();
        #[cfg(feature = "pages")]
        let login_page_route = login_page_route.clone();
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

            if !wants_json && let Some(info) = res.extensions().get::<StoreFailureInfo>().cloned() {
                res = render_store_failure_page(
                    res,
                    info,
                    #[cfg(feature = "pages")]
                    &pages,
                    #[cfg(feature = "pages")]
                    &login_page_route,
                );
            }

            if wants_json {
                res = jsonify_redirect(res);
            }

            res
        }
    })
}

/// A store failure on its way to a browser: the JSON body the handler
/// produced is swapped for the error page. Only a message the store opted
/// into showing survives; anything else becomes a generic apology, so
/// nothing about the store is implied.
///
/// The response is rewritten rather than rebuilt, so everything the layer
/// staged on the way out - the session cookie, `X-Auth-Token` - still
/// reaches the browser.
fn render_store_failure_page(
    res: Response,
    info: StoreFailureInfo,
    #[cfg(feature = "pages")] pages: &Arc<dyn crate::pages::Pages>,
    #[cfg(feature = "pages")] login_page_route: &str,
) -> Response {
    use axum::http::{HeaderValue, header};

    let message = if info.public {
        info.message.clone()
    } else {
        "Please try again in a moment.".to_string()
    };

    #[cfg(feature = "pages")]
    let (body, content_type) = {
        let view = crate::pages::ErrorTemplate {
            status: info.status.as_u16(),
            message: &message,
            login_page_route,
        };
        (
            pages.render_error(&view),
            HeaderValue::from_static("text/html; charset=utf-8"),
        )
    };
    #[cfg(not(feature = "pages"))]
    let (body, content_type) = (
        message,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    let (mut parts, _) = res.into_parts();
    parts.status = info.status;
    parts.headers.insert(header::CONTENT_TYPE, content_type);
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, axum::body::Body::from(body))
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

    let (status, body) = match error {
        Some(error) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::to_value(FlowError {
                error,
                next: location.clone(),
            })
            .unwrap(),
        ),
        None => (
            StatusCode::OK,
            serde_json::to_value(FlowResult {
                next: location.clone(),
                message,
            })
            .unwrap(),
        ),
    };

    let (mut parts, _) = res.into_parts();
    parts.status = status;
    parts.headers.remove(header::LOCATION);
    parts.headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);

    axum::response::Response::from_parts(parts, axum::body::Body::from(body.to_string()))
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
///
/// The [`MaybeStoreError`](crate::store::MaybeStoreError) bound is the point:
/// a store error is diverted into a [`StoreFailure`] here, BEFORE anything
/// can call `Display` on it, so a store's own words - which may name hosts,
/// credentials or SQL - can never reach a `?error=` query param (nor the
/// `422 {"error"}` body [`jsonify_redirect`] makes of it). An error type
/// that can carry a store error and does not implement the trait will not
/// compile at the call site.
pub(crate) fn error_redirect<E, Err>(
    routes: &Routes<String>,
    err: Err,
    fallback: &str,
    next: Option<&str>,
) -> Result<String, StoreFailure<E>>
where
    Err: std::fmt::Display + crate::ratelimit::MaybeRateLimited + crate::store::MaybeStoreError<E>,
{
    let err = err.store_error()?;
    if let Some(limited) = err.rate_limited() {
        return Ok(paused_url(routes, limited, next));
    }
    let separator = if fallback.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{fallback}{separator}error={}",
        urlencoding::encode(&err.to_string())
    ))
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
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
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
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
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
            Err(CodeInitError::Store(err)) => Err(err.into()),
            Err(err) => Ok(Redirect::to(&error_redirect(
                &routes,
                err,
                &with_method(page, method),
                next.as_deref(),
            )?)
            .into_response()),
        },
        Some(code) => match auth.code_verify::<Ch>(&identifier, &code, intent).await {
            Ok((auth, next)) => complete_login(auth, next).await,
            Err(CodeVerifyError::Store(err)) => Err(err.into()),
            Err(err) => Ok(Redirect::to(&error_redirect(
                &routes,
                err,
                &format!(
                    "{action_route}?address={}",
                    urlencoding::encode(&identifier)
                ),
                next.as_deref(),
            )?)
            .into_response()),
        },
    }
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

    /// The page set the cookie layer renders browser-facing failures with;
    /// see [`crate::config::AutheryConfig::pages`].
    #[cfg(feature = "pages")]
    fn pages(&self) -> std::sync::Arc<dyn crate::pages::Pages>;

    /// The OpenAPI document for the routes this config mounts, with the
    /// defaults from [`crate::openapi::OpenApiOptions`].
    #[cfg(feature = "openapi")]
    fn openapi(&self) -> crate::openapi::Document {
        self.openapi_with(crate::openapi::OpenApiOptions::default())
    }

    /// The OpenAPI document, shaped by `options`.
    #[cfg(feature = "openapi")]
    fn openapi_with(&self, options: crate::openapi::OpenApiOptions) -> crate::openapi::Document {
        use crate::openapi::Describe;

        let routes = self.routes();
        let mut d = Describe::new(
            options.schema_settings,
            self.bearer_auth(),
            self.cookie_names().session_id,
        );
        let mut paths: std::collections::BTreeMap<String, crate::openapi::PathItem> =
            Default::default();
        for endpoint in Endpoint::all() {
            // Page-class operations - the HTML GETs and the two POSTs that
            // render a page directly - are of no use to an API client.
            if endpoint.response_set().is_page() && !options.pages {
                continue;
            }
            let op = endpoint.describe(&mut d);
            paths
                .entry(endpoint.path(routes).to_string())
                .or_default()
                .insert(endpoint.method().as_str().to_lowercase(), op);
        }
        d.finish(paths)
    }

    fn router<St, S>(&self) -> Router<S>
    where
        AutheryConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AutheryStore + FromRef<S> + Send + Sync + 'static,
    {
        let routes = self.routes();
        let router = Endpoint::all()
            .into_iter()
            .fold(Router::new(), |router, endpoint| {
                router.route(endpoint.path(routes), endpoint.handler::<St, S>())
            });

        config_cookie_layer(self, router)
    }

    /// The same routes as [`Self::router`], registered through aide's typed
    /// routing so `finish_api` documents them alongside the application's own
    /// routes. Pages are included: aide documents whatever it routes.
    ///
    /// aide collects components from its own schema generator only, so the
    /// security schemes the operations refer to have to be inserted
    /// afterwards; see [`Self::aide_security_schemes`].
    ///
    /// ```ignore
    /// let mut api = aide::openapi::OpenApi::default();
    /// let app = aide::axum::ApiRouter::new()
    ///     .merge(config.api_router::<MyStore, AppState>())
    ///     .finish_api(&mut api)
    ///     .with_state(state);
    /// let components = api.components.get_or_insert_with(Default::default);
    /// for (name, scheme) in config.aide_security_schemes() {
    ///     components
    ///         .security_schemes
    ///         .insert(name, aide::openapi::ReferenceOr::Item(scheme));
    /// }
    /// ```
    #[cfg(feature = "aide")]
    fn api_router<St, S>(&self) -> ::aide::axum::ApiRouter<S>
    where
        AutheryConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AutheryStore + FromRef<S> + Send + Sync + 'static,
    {
        let routes = self.routes();
        let bearer = self.bearer_auth();
        let router =
            Endpoint::all()
                .into_iter()
                .fold(::aide::axum::ApiRouter::new(), |router, endpoint| {
                    router.api_route(endpoint.path(routes), endpoint.api_handler::<St, S>(bearer))
                });

        config_cookie_layer(self, router)
    }

    /// The security schemes [`Self::api_router`]'s operations refer to: the
    /// session cookie always, and `bearer` when
    /// [`crate::config::AutheryConfig::bearer_auth`] is on. Insert them into
    /// `api.components.security_schemes` after `finish_api`.
    #[cfg(feature = "aide")]
    fn aide_security_schemes(&self) -> Vec<(String, ::aide::openapi::SecurityScheme)> {
        crate::axum::aide::security_schemes(self.bearer_auth(), self.cookie_names().session_id)
    }
}

/// The cookie layer with `config`'s settings, for either router type.
fn config_cookie_layer<C, R>(config: &C, router: R) -> R
where
    C: AxumRouter + ?Sized,
    R: CookieLayered,
{
    cookie_layered(
        router,
        config.cookie_key(),
        config.bearer_auth(),
        config.bearer_token_prefix(),
        config.previous_cookie_keys(),
        config.cookie_names().session_id,
        #[cfg(feature = "pages")]
        config.pages(),
        #[cfg(feature = "pages")]
        config.routes().pages.login.to_string(),
    )
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

    #[cfg(feature = "pages")]
    fn pages(&self) -> std::sync::Arc<dyn crate::pages::Pages> {
        self.pages.clone()
    }
}

pub(crate) async fn post_user_logout<St>(
    auth: AxumAuthery<St>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    let post_logout = auth.routes.pages.post_logout.clone();

    Ok((auth.log_out().await?, Redirect::to(&post_logout)).into_response())
}

pub(crate) async fn get_user_verify_session<St>(
    auth: AxumAuthery<St>,
) -> Result<Response, StoreFailure<St::Error>>
where
    St: AutheryStore,
{
    Ok(if auth.logged_in().await? {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
    .into_response())
}

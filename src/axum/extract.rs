use super::cookies::{AxumAutheryCookies, JarHandle, SharedCookieJar};
use crate::{config::AutheryConfig, core::CoreAuthery, store::AutheryStore};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::IntoResponseParts,
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use std::convert::Infallible;

impl<S: AutheryStore> IntoResponseParts for CoreAuthery<S, AxumAutheryCookies> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.cookies.into_response_parts(res)
    }
}

impl<S, St> FromRequestParts<S> for CoreAuthery<St, AxumAutheryCookies>
where
    St: AutheryStore,
    AutheryConfig: FromRef<S>,
    S: Send + Sync,
    St: AutheryStore + FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Infallible> {
        let config = AutheryConfig::from_ref(state);

        // When the cookie-propagation middleware is present it has already built
        // the jar and shared it via request extensions; use that so mutations
        // survive to the response without the handler returning the auth service.
        // Otherwise fall back to an owned jar written via IntoResponseParts.
        let (jar, fallbacks) = match parts.extensions.get::<SharedCookieJar>() {
            Some(shared) => (JarHandle::Shared(shared.clone()), shared.fallbacks.clone()),
            None => (
                JarHandle::Owned(PrivateCookieJar::from_headers(
                    &parts.headers,
                    Key::from(config.key.as_bytes()),
                )),
                std::sync::Arc::new(
                    config
                        .previous_keys
                        .iter()
                        .map(|key| {
                            PrivateCookieJar::from_headers(
                                &parts.headers,
                                Key::from(key.as_bytes()),
                            )
                        })
                        .collect(),
                ),
            ),
        };

        let bearer_token = config
            .bearer_auth
            .then(|| parts.headers.get(axum::http::header::AUTHORIZATION))
            .flatten()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            // A configured token prefix is part of the wire format: required
            // and stripped, so the rest of the crate only sees session ids.
            .and_then(|token| match &config.bearer_token_prefix {
                Some(prefix) => token.strip_prefix(prefix.as_str()),
                None => Some(token),
            })
            .map(str::to_string);

        let cookies = AxumAutheryCookies {
            jar,
            fallbacks,
            https_only: config.https_only,
        };
        let store = St::from_ref(state);

        let session_meta = crate::models::SessionMeta {
            user_agent: parts
                .headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(|ua| ua.chars().take(512).collect()),
            ip_address: config
                .client_ip_header
                .as_deref()
                .and_then(|name| parts.headers.get(name))
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(|ip| ip.trim().to_string())
                .filter(|ip| !ip.is_empty())
                .or_else(|| {
                    parts
                        .extensions
                        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                        .map(|info| info.0.ip().to_string())
                }),
        };

        Ok(CoreAuthery {
            allow_signup: config.allow_signup,
            allow_login: config.allow_login,
            session_lifetime: config.session_lifetime,
            max_concurrent_sessions: config.max_concurrent_sessions,
            idle_timeout: config.idle_timeout,
            rate_limiter: config.rate_limiter,
            events: config.events,
            bearer_token,
            session_meta,
            cookie_names: config.cookie_names,
            routes: config.routes,
            cookies,
            store,
            #[cfg(feature = "email")]
            email: config.email,
            #[cfg(feature = "password")]
            pass: config.pass,
            #[cfg(feature = "oauth")]
            oauth: config.oauth,
            #[cfg(feature = "webauthn")]
            webauthn: config.webauthn,
            #[cfg(feature = "totp")]
            totp: config.totp,
            #[cfg(feature = "sms")]
            sms: config.sms,
            #[cfg(feature = "mfa")]
            mfa_policy: config.mfa_policy,
            #[cfg(feature = "pages")]
            pages: config.pages,
        })
    }
}

/// A `{ "error": … }` JSON body with the given status.
pub(crate) fn json_error(
    status: axum::http::StatusCode,
    err: &impl std::fmt::Display,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        status,
        axum::Json(serde_json::json!({ "error": err.to_string() })),
    )
        .into_response()
}

/// Body extractor for the flow endpoints: accepts the same payload as either
/// an HTML form (`application/x-www-form-urlencoded`) or JSON
/// (`application/json`), so browsers and API clients POST to the same routes.
///
/// A recognised `Content-Type` decides the parser. Without one — missing,
/// `text/plain`, anything else — the body is tried as JSON first and as a form
/// second. Rejections carry a `{ "error": … }` JSON body: `422` when the
/// declared format fails to parse, `415` when the format was unclear and
/// neither parse succeeds.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormOrJson<T>(pub T);

enum DeclaredBody {
    Json,
    Form,
    Unclear,
}

impl<S, T> axum::extract::FromRequest<S> for FormOrJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = axum::response::Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        use axum::http::StatusCode;

        let declared = match req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim_start().to_ascii_lowercase())
        {
            Some(ct) if ct.starts_with("application/json") => DeclaredBody::Json,
            Some(ct) if ct.starts_with("application/x-www-form-urlencoded") => DeclaredBody::Form,
            _ => DeclaredBody::Unclear,
        };

        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(|err| json_error(err.status(), &err))?;

        let value = match declared {
            DeclaredBody::Json => serde_json::from_slice::<T>(&bytes)
                .map_err(|err| json_error(StatusCode::UNPROCESSABLE_ENTITY, &err))?,
            DeclaredBody::Form => serde_urlencoded::from_bytes::<T>(&bytes)
                .map_err(|err| json_error(StatusCode::UNPROCESSABLE_ENTITY, &err))?,
            DeclaredBody::Unclear => serde_json::from_slice::<T>(&bytes)
                .or_else(|_| serde_urlencoded::from_bytes::<T>(&bytes))
                .map_err(|_| {
                    json_error(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        &"Expected a JSON (application/json) or form-encoded \
                          (application/x-www-form-urlencoded) body",
                    )
                })?,
        };

        Ok(FormOrJson(value))
    }
}

#[cfg(test)]
mod form_or_json_tests {
    use super::FormOrJson;
    use axum::{
        body::{Body, to_bytes},
        extract::FromRequest,
        http::{Request, StatusCode},
        response::Response,
    };
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq)]
    struct Probe {
        name: String,
        next: Option<String>,
    }

    async fn extract(content_type: Option<&str>, body: &str) -> Result<Probe, Response> {
        let mut req = Request::builder().method("POST").uri("/");
        if let Some(content_type) = content_type {
            req = req.header("content-type", content_type);
        }
        let req = req.body(Body::from(body.to_string())).unwrap();
        FormOrJson::<Probe>::from_request(req, &())
            .await
            .map(|FormOrJson(value)| value)
    }

    async fn error_body(res: Response) -> (StatusCode, serde_json::Value) {
        let status = res.status();
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "application/json"
        );
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn probe(name: &str, next: Option<&str>) -> Probe {
        Probe {
            name: name.into(),
            next: next.map(Into::into),
        }
    }

    #[tokio::test]
    async fn json_content_type_parses_json() {
        let got = extract(Some("application/json"), r#"{"name":"a","next":"/x"}"#).await;
        assert_eq!(got.unwrap(), probe("a", Some("/x")));
    }

    #[tokio::test]
    async fn form_content_type_parses_form() {
        let got = extract(
            Some("application/x-www-form-urlencoded"),
            "name=a&next=%2Fx",
        )
        .await;
        assert_eq!(got.unwrap(), probe("a", Some("/x")));
    }

    #[tokio::test]
    async fn content_type_parameters_are_tolerated() {
        let got = extract(Some("application/json; charset=utf-8"), r#"{"name":"a"}"#).await;
        assert_eq!(got.unwrap(), probe("a", None));
    }

    #[tokio::test]
    async fn missing_content_type_sniffs_json() {
        let got = extract(None, r#"{"name":"a"}"#).await;
        assert_eq!(got.unwrap(), probe("a", None));
    }

    #[tokio::test]
    async fn missing_content_type_sniffs_form() {
        let got = extract(None, "name=a").await;
        assert_eq!(got.unwrap(), probe("a", None));
    }

    #[tokio::test]
    async fn unknown_content_type_sniffs_json() {
        let got = extract(Some("text/plain"), r#"{"name":"a"}"#).await;
        assert_eq!(got.unwrap(), probe("a", None));
    }

    #[tokio::test]
    async fn declared_json_that_fails_to_parse_is_422_with_json_error() {
        let res = extract(Some("application/json"), "name=a")
            .await
            .unwrap_err();
        let (status, body) = error_body(res).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string(), "{body}");
    }

    #[tokio::test]
    async fn declared_form_that_fails_to_parse_is_422_with_json_error() {
        let res = extract(Some("application/x-www-form-urlencoded"), "next=%2Fx")
            .await
            .unwrap_err();
        let (status, body) = error_body(res).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"].as_str().unwrap().contains("name"),
            "names the missing field: {body}"
        );
    }

    #[tokio::test]
    async fn unclear_content_type_with_unparseable_body_is_415() {
        let res = extract(Some("text/plain"), "not json, and not a form either")
            .await
            .unwrap_err();
        let (status, body) = error_body(res).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let error = body["error"].as_str().unwrap();
        assert!(error.contains("application/json"), "{error}");
        assert!(
            error.contains("application/x-www-form-urlencoded"),
            "{error}"
        );
    }
}

//! Transport-level tests for the axum router, run with:
//!   cargo test -p authery --all-features --test axum_router
#![cfg(all(
    feature = "axum",
    feature = "password",
    feature = "email",
    feature = "mfa",
    feature = "user"
))]

mod common;

use authery::mfa::MfaPolicy;
use authery::prelude::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::FromRef,
    http::{Request, StatusCode, header},
};
use common::{PlaintextHasher, TestStore};
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;

#[derive(Clone, FromRef)]
struct AppState {
    store: TestStore,
    auth: AutheryConfig,
}

fn config() -> AutheryConfig {
    let base = Url::parse("http://localhost:3000").unwrap();
    AutheryConfig::new(
        "A".repeat(64),
        Routes::default(),
        PasswordConfig::new().with_hasher(PlaintextHasher),
        EmailConfig::new(
            base.clone(),
            SmtpSettings::new("smtp://localhost:1", "test@example.com"),
        ),
        #[cfg(feature = "oauth")]
        authery::oauth::OAuthConfig::new(base.clone()),
        #[cfg(feature = "webauthn")]
        authery::webauthn::WebauthnConfig::new(base.clone(), "authery-tests").unwrap(),
        #[cfg(feature = "totp")]
        authery::totp::TotpConfig::new("authery-tests"),
        #[cfg(feature = "sms")]
        authery::sms::SmsConfig::new(common::TestSmsSender::default()),
    )
    .unwrap()
    .with_https_only(false)
    .with_mfa_policy(MfaPolicy {
        require_for_password: false,
        ..Default::default()
    })
}

fn app_with(config: AutheryConfig, store: TestStore) -> Router {
    let router = config.router::<TestStore, AppState>();
    router.with_state(AppState {
        store,
        auth: config,
    })
}

fn app(store: TestStore) -> Router {
    app_with(config(), store)
}

async fn json_body(res: axum::response::Response) -> Value {
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        panic!("not JSON: {}", String::from_utf8_lossy(&bytes));
    })
}

/// API clients POST the login form as JSON and get the JSON flow contract
/// back — `200 {"next"}` on success, `422 {"error","next"}` on failure.
#[tokio::test]
async fn password_login_accepts_json_body() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));

    let login = |password: &str| {
        Request::post("/login/password")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(
                json!({ "password_id": "alice@x.com", "password": password }).to_string(),
            ))
            .unwrap()
    };

    let res = app(store.clone()).oneshot(login("wrong")).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(res).await;
    assert!(body["error"].is_string(), "{body}");
    assert!(body["next"].is_string(), "{body}");

    let res = app(store).oneshot(login("hunter2-hunter2")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().contains_key(header::SET_COOKIE),
        "session cookie set"
    );
    let body = json_body(res).await;
    assert_eq!(body["next"], "/");
}

/// The JSON flow bodies have exactly the documented shape: no `message`
/// key when there is no message, and `error` plus `next` on failure.
#[tokio::test]
async fn json_flow_bodies_have_exact_shape() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));
    let login = |password: &str| {
        Request::post("/login/password")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(
                json!({ "password_id": "alice@x.com", "password": password }).to_string(),
            ))
            .unwrap()
    };

    let ok = json_body(
        app(store.clone())
            .oneshot(login("hunter2-hunter2"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(ok, json!({ "next": "/" }));

    let err = json_body(app(store).oneshot(login("wrong")).await.unwrap()).await;
    assert_eq!(
        err.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["error", "next"]
    );
    assert_eq!(
        err["next"],
        "/login?method=password&error=Wrong%20email%20or%20password"
    );
}

/// Browsers keep working exactly as before.
#[tokio::test]
async fn password_login_still_accepts_form_body() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));

    let res = app(store)
        .oneshot(
            Request::post("/login/password")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "password_id=alice%40x.com&password=hunter2-hunter2",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/");
    assert!(res.headers().contains_key(header::SET_COOKIE));
}

/// A store failure with no public rendering is a 500 that says nothing
/// about the underlying error, as JSON for API clients and as the error
/// page for browsers.
#[tokio::test]
async fn hidden_store_error_is_generic_500() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));
    store.fail_next(common::TestError::Internal(
        "postgres://user:secret@db/authery refused".into(),
    ));

    let res = app(store.clone())
        .oneshot(
            Request::post("/login/password")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .body(Body::from(
                    json!({ "password_id": "alice@x.com", "password": "hunter2-hunter2" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = json_body(res).await;
    assert_eq!(body, json!({ "error": "Internal server error" }));

    store.fail_next(common::TestError::Internal("secret".into()));
    let res = app(store)
        .oneshot(
            Request::post("/login/password")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ACCEPT, "text/html")
                .body(Body::from(
                    "password_id=alice%40x.com&password=hunter2-hunter2",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        res.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let html = String::from_utf8(
        to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("Something went wrong"), "{html}");
    assert!(!html.contains("secret"), "leaked: {html}");
}

/// A store that opts in with `PublicError` gets its status and message
/// through, in both modes.
#[tokio::test]
async fn public_store_error_is_rendered() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));

    for accept in ["application/json", "text/html"] {
        store.fail_next(common::TestError::Taken);
        let res = app(store.clone())
            .oneshot(
                Request::post("/login/password")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, accept)
                    .body(Body::from(
                        json!({ "password_id": "alice@x.com", "password": "hunter2-hunter2" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT, "{accept}");
        let content_type = res.headers()[header::CONTENT_TYPE].to_str().unwrap();
        match accept {
            "application/json" => assert!(
                content_type.starts_with("application/json"),
                "{content_type}"
            ),
            _ => assert!(content_type.starts_with("text/html"), "{content_type}"),
        }
        let text = String::from_utf8(
            to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("That address is taken"), "{accept}: {text}");
    }
}

/// The error page is a rewrite of the handler's response, not a fresh one:
/// what the cookie layer staged on the way out still reaches the browser.
#[tokio::test]
async fn store_error_page_keeps_the_staged_cookies() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));
    // The login creates the session - staging the cookie - and only then
    // reads it back to look for a pending second factor.
    store.fail_session_next(common::TestError::Internal("secret".into()));

    let res = app(store)
        .oneshot(
            Request::post("/login/password")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ACCEPT, "text/html")
                .body(Body::from(
                    "password_id=alice%40x.com&password=hunter2-hunter2",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        res.headers().contains_key(header::SET_COOKIE),
        "the staged session cookie was dropped: {:?}",
        res.headers()
    );
}

/// No route may put a store error's `Display` on the wire. The store is
/// armed to fail EVERY call with a marker string, then every documented
/// (method, path) is called - as a browser and as a JSON client, with a
/// logged-in cookie - and the marker must appear in neither the body nor
/// the `Location` header. Endpoints that need a body the sweep cannot
/// supply simply never reach the store; the rest prove the class is closed.
#[cfg(feature = "openapi")]
#[tokio::test]
async fn no_route_leaks_a_store_error_to_the_wire() {
    use authery::openapi::OpenApiOptions;

    const MARKER: &str = "MARKER-xyz";

    let config = config();
    let doc = config
        .openapi_with(OpenApiOptions::default().with_pages(true))
        .to_json();
    let mut operations: Vec<(String, String)> = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            operations.push((method.to_uppercase(), path.clone()));
        }
    }
    operations.sort();
    assert!(operations.len() > 20, "{operations:?}");

    // A superset body: every flow form deserializes from it, so a POST gets
    // past its extractor and reaches the store.
    let body = json!({
        "email": "alice@x.com",
        "password_id": "alice@x.com",
        "password": "hunter2-hunter2",
        "new_password": "hunter2-hunter2",
        "code": "123456",
        "id": "6f0b8f1e-0c1a-4f9e-9a3a-1b2c3d4e5f60",
        "credential_id": "00",
        "provider": "test",
        "display_name": "alice",
        "name": "alice",
        "next": "/",
    })
    .to_string();
    // And a superset query string, for the callback GETs.
    let query = "code=abcdef&state=abcdef&address=alice%40x.com&purpose=login\
                 &provider=test&next=%2F";

    // A real session cookie, so secured routes get past their guard.
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));
    let login = app_with(config.clone(), store.clone())
        .oneshot(
            Request::post("/login/password")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "password_id=alice%40x.com&password=hunter2-hunter2",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    store.fail_all(common::TestError::Internal(MARKER.into()));

    for (method, path) in &operations {
        for accept in ["text/html", "application/json"] {
            let uri = if method == "GET" {
                format!("{path}?{query}")
            } else {
                path.clone()
            };
            let res = app_with(config.clone(), store.clone())
                .oneshot(
                    Request::builder()
                        .method(method.as_str())
                        .uri(&uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::ACCEPT, accept)
                        .header(header::COOKIE, &cookie)
                        .body(Body::from(body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();

            let location = res
                .headers()
                .get(header::LOCATION)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            assert!(
                !location.contains(MARKER),
                "{method} {path} ({accept}) leaked the store error into Location: {location}"
            );
            let text =
                String::from_utf8_lossy(&to_bytes(res.into_body(), usize::MAX).await.unwrap())
                    .to_string();
            assert!(
                !text.contains(MARKER),
                "{method} {path} ({accept}) leaked the store error into the body: {text}"
            );
        }
    }
}

/// The TOTP second factor reaches the store only after the pending-session
/// lookup has succeeded, so the blanket sweep cannot get there: this arms
/// just `get_totp` and checks the nested store error is diverted.
#[cfg(feature = "totp")]
#[tokio::test]
async fn mfa_totp_store_error_does_not_leak() {
    const MARKER: &str = "MARKER-totp";

    let config = config().with_mfa_policy(MfaPolicy {
        require_for_password: true,
        ..Default::default()
    });

    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));

    // A password login under this policy lands in a pending MFA session.
    let pending = app_with(config.clone(), store.clone())
        .oneshot(
            Request::post("/login/password")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "password_id=alice%40x.com&password=hunter2-hunter2",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = pending.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    store.fail_totp_next(common::TestError::Internal(MARKER.into()));

    let res = app_with(config, store)
        .oneshot(
            Request::post("/login/mfa/totp")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from("code=123456"))
                .unwrap(),
        )
        .await
        .unwrap();

    let location = res
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        !location.contains(MARKER),
        "leaked into Location: {location}"
    );
    let text =
        String::from_utf8_lossy(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).to_string();
    assert!(!text.contains(MARKER), "leaked into the body: {text}");
}

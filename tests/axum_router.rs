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

fn app(store: TestStore) -> Router {
    let base = Url::parse("http://localhost:3000").unwrap();
    let config = AutheryConfig::new(
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
    });

    let router = config.router::<TestStore, AppState>();
    router.with_state(AppState {
        store,
        auth: config,
    })
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

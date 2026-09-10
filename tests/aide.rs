//! aide integration: run with `cargo test -p authery --all-features --test aide`
#![cfg(all(
    feature = "aide",
    feature = "password",
    feature = "email",
    feature = "mfa",
    feature = "user"
))]

mod common;

use aide::{axum::ApiRouter, openapi::OpenApi, openapi::ReferenceOr};
use authery::mfa::MfaPolicy;
use authery::openapi::OpenApiOptions;
use authery::prelude::*;
use axum::extract::FromRef;
use common::{PlaintextHasher, TestStore};
use serde_json::Value;
use url::Url;

#[derive(Clone, FromRef)]
struct AppState {
    store: TestStore,
    auth: AutheryConfig,
}

// The same configuration as `tests/openapi.rs`, copied so this file stands
// alone.
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
    .with_bearer_auth(true)
    .with_mfa_policy(MfaPolicy {
        require_for_password: false,
        ..Default::default()
    })
}

fn operations(doc: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (method, _) in item.as_object().unwrap() {
            out.push((method.to_uppercase(), path.clone()));
        }
    }
    out.sort();
    out
}

/// Builds the aide document for the authery routes, with the security
/// schemes authery describes inserted the way an application would.
fn document(config: &AutheryConfig) -> (OpenApi, axum::Router) {
    let mut api = OpenApi::default();
    let router = ApiRouter::new()
        .merge(config.api_router::<TestStore, AppState>())
        .finish_api(&mut api)
        .with_state(AppState {
            store: TestStore::default(),
            auth: config.clone(),
        });
    let components = api.components.get_or_insert_with(Default::default);
    for (name, scheme) in config.aide_security_schemes() {
        components
            .security_schemes
            .insert(name, ReferenceOr::Item(scheme));
    }
    (api, router)
}

/// Every operation `openapi()` documents (pages included, since aide sees the
/// whole router) is documented by aide too, with a request body on the
/// password login carrying both media types.
#[test]
fn api_router_documents_every_endpoint() {
    let config = config();
    let (api, _router) = document(&config);

    let json = serde_json::to_value(&api).unwrap();
    let neutral = config
        .openapi_with(OpenApiOptions::default().with_pages(true))
        .to_json();
    assert_eq!(operations(&json), operations(&neutral));

    let body = &json["paths"]["/login/password"]["post"]["requestBody"]["content"];
    assert!(body.get("application/json").is_some(), "{body}");
    assert!(
        body.get("application/x-www-form-urlencoded").is_some(),
        "{body}"
    );
}

/// The rows' summaries, tags, ids and responses reach the aide document, and
/// the security schemes authery describes can be dropped straight in.
#[test]
fn operations_carry_the_row_metadata() {
    let config = config();
    let (api, _router) = document(&config);
    let json = serde_json::to_value(&api).unwrap();

    let login = &json["paths"]["/login/password"]["post"];
    assert_eq!(login["operationId"], "login_password");
    assert_eq!(login["summary"], "Log in with a password");
    assert_eq!(login["tags"][0], "Password");
    assert!(login["responses"]["303"].is_object(), "{login}");
    assert!(login["responses"]["422"].is_object(), "{login}");
    assert!(login["responses"]["500"].is_object(), "{login}");
    // A fresh login hands the token to bearer clients.
    assert!(
        login["responses"]["200"]["headers"]["X-Auth-Token"].is_object(),
        "{login}"
    );

    // Secured operations require the session cookie, or a bearer token.
    let logout = &json["paths"]["/logout"]["post"];
    assert_eq!(logout["security"].as_array().unwrap().len(), 2, "{logout}");

    // The page routes are documented as HTML.
    let page = &json["paths"]["/login"]["get"];
    assert!(
        page["responses"]["200"]["content"]["text/html"].is_object(),
        "{page}"
    );

    let schemes = &json["components"]["securitySchemes"];
    assert_eq!(schemes["session_cookie"]["in"], "cookie", "{schemes}");
    assert_eq!(schemes["bearer"]["scheme"], "bearer", "{schemes}");
}

/// The passkey ceremonies take an opaque JSON credential, and the register
/// start takes the form-or-JSON body its extractor accepts.
#[cfg(feature = "webauthn")]
#[test]
fn passkey_bodies_are_documented() {
    let config = config();
    let (api, _router) = document(&config);
    let json = serde_json::to_value(&api).unwrap();

    let finish = &json["paths"]["/login/webauthn/finish"]["post"]["requestBody"]["content"];
    assert_eq!(finish["application/json"]["schema"]["type"], "object");
    assert!(finish.get("application/x-www-form-urlencoded").is_none());

    let start = &json["paths"]["/user/webauthn/register/start"]["post"]["requestBody"]["content"];
    assert!(start.get("application/json").is_some(), "{start}");
    assert!(
        start.get("application/x-www-form-urlencoded").is_some(),
        "{start}"
    );
}

/// The cookie layer is applied to the router aide hands back, exactly as
/// `router()` applies it: a successful password login through the
/// `api_router()`-built app sets the session cookie and, with bearer auth on,
/// hands the token back in `X-Auth-Token`. Both headers come from the layer
/// and from nowhere else.
#[tokio::test]
async fn the_api_router_applies_the_cookie_layer() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let config = config();
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2-hunter2"));

    let mut api = OpenApi::default();
    let router = ApiRouter::new()
        .merge(config.api_router::<TestStore, AppState>())
        .finish_api(&mut api)
        .with_state(AppState {
            store,
            auth: config.clone(),
        });

    let res = router
        .oneshot(
            Request::post("/login/password")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "password_id": "alice@x.com",
                        "password": "hunter2-hunter2",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(header::SET_COOKIE).is_some(),
        "the layer serialises the session cookie: {:?}",
        res.headers()
    );
    assert!(
        res.headers().get("x-auth-token").is_some(),
        "the layer exposes the bearer token: {:?}",
        res.headers()
    );
}

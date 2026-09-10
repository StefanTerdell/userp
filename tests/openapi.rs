//! The OpenAPI document: run with `cargo test -p authery --all-features --test openapi`
#![cfg(all(
    feature = "openapi",
    feature = "password",
    feature = "email",
    feature = "mfa",
    feature = "user"
))]

mod common;

use authery::mfa::MfaPolicy;
use authery::openapi::OpenApiOptions;
use authery::prelude::*;
use axum::{
    Router,
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
};
use common::{PlaintextHasher, TestStore};
use schemars::generate::SchemaSettings;
use serde_json::Value;
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

/// Both libraries' document types accept what authery emits, with every
/// path and schema intact.
#[test]
fn round_trips_into_utoipa_and_aide() {
    let doc = config().openapi();
    let json = doc.to_json();
    let ops = operations(&json);
    assert!(ops.len() > 20, "{ops:?}");
    let schemas: Vec<_> = json["components"]["schemas"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert!(schemas.iter().any(|s| s == "FlowResult"), "{schemas:?}");

    let utoipa: utoipa::openapi::OpenApi = doc.convert().expect("utoipa");
    let back = serde_json::to_value(&utoipa).unwrap();
    assert_eq!(operations(&back), ops);
    assert_eq!(
        back["components"]["schemas"].as_object().unwrap().len(),
        schemas.len()
    );

    let aide: aide::openapi::OpenApi = doc.convert().expect("aide");
    let back = serde_json::to_value(&aide).unwrap();
    assert_eq!(operations(&back), ops);
    assert_eq!(
        back["components"]["schemas"].as_object().unwrap().len(),
        schemas.len()
    );

    // Paths and schema counts are the cheap half. The operation's own
    // detail - which statuses it answers with, both media types it accepts,
    // the security alternatives - has to survive the conversion too, or the
    // document is only nominally compatible.
    let login = |doc: &Value| doc["paths"]["/login/password"]["post"].clone();
    let mine = login(&json);
    let response_keys = |op: &Value| {
        let mut keys: Vec<String> = op["responses"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    let media_types = |op: &Value| {
        let mut keys: Vec<String> = op["requestBody"]["content"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    assert_eq!(response_keys(&mine), ["200", "303", "422", "4XX", "500"]);
    assert_eq!(
        media_types(&mine),
        ["application/json", "application/x-www-form-urlencoded"]
    );

    // `/logout` carries the security list; `/login/password` carries none,
    // and both facts have to survive.
    let logout = |doc: &Value| doc["paths"]["/logout"]["post"].clone();
    assert_eq!(
        logout(&json)["security"],
        serde_json::json!([{ "session_cookie": [] }, { "bearer": [] }])
    );

    for (name, back) in [
        ("utoipa", serde_json::to_value(&utoipa).unwrap()),
        ("aide", serde_json::to_value(&aide).unwrap()),
    ] {
        let theirs = login(&back);
        assert_eq!(response_keys(&theirs), response_keys(&mine), "{name}");
        assert_eq!(media_types(&theirs), media_types(&mine), "{name}");
        assert!(
            theirs["security"].as_array().is_none_or(|s| s.is_empty()),
            "{name}: {theirs}"
        );
        assert_eq!(
            logout(&back)["security"],
            logout(&json)["security"],
            "{name}"
        );
    }
}

/// Every documented operation exists on the real router: nothing 404s or 405s.
#[tokio::test]
async fn every_documented_operation_is_mounted() {
    let config = config();
    let doc = config
        .openapi_with(OpenApiOptions::default().with_pages(true))
        .to_json();
    let app: Router = config.router::<TestStore, AppState>().with_state(AppState {
        store: TestStore::default(),
        auth: config.clone(),
    });

    for (method, path) in operations(&doc) {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.as_str())
                    .uri(&path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(res.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert_ne!(
            res.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
    }
}

/// Pages are out unless asked for.
#[test]
fn pages_are_opt_in() {
    let without = config().openapi().to_json();
    let with = config()
        .openapi_with(OpenApiOptions::default().with_pages(true))
        .to_json();
    assert!(!operations(&without).contains(&("GET".into(), "/login".into())));
    assert!(operations(&with).contains(&("GET".into(), "/login".into())));
    assert!(operations(&with).len() > operations(&without).len());
}

/// The dialect follows the settings: 3.1.0 and type arrays by default,
/// 3.0.3 and `nullable` with the openapi3 preset.
#[test]
fn dialect_follows_schema_settings() {
    let default = config().openapi().to_json();
    assert_eq!(default["openapi"], "3.1.0");
    let props = &default["components"]["schemas"]["FlowResult"]["properties"]["message"];
    assert!(props.get("nullable").is_none(), "{props}");

    let legacy = config()
        .openapi_with(OpenApiOptions::default().with_schema_settings(SchemaSettings::openapi3()))
        .to_json();
    assert_eq!(legacy["openapi"], "3.0.3");
    let props = &legacy["components"]["schemas"]["FlowResult"]["properties"]["message"];
    assert_eq!(props["nullable"], true, "{props}");
}

/// Security: the session cookie always, bearer when enabled, and the
/// X-Auth-Token header on a login operation's success response.
#[test]
fn security_schemes_match_config() {
    let doc = config().openapi().to_json();
    let schemes = &doc["components"]["securitySchemes"];
    assert_eq!(schemes["session_cookie"]["in"], "cookie");
    assert_eq!(schemes["bearer"]["scheme"], "bearer");
    let login = &doc["paths"]["/login/password"]["post"];
    assert!(
        login["responses"]["200"]["headers"]["X-Auth-Token"].is_object(),
        "{login}"
    );
    let logout = &doc["paths"]["/logout"]["post"];
    assert!(
        logout["security"].as_array().unwrap().len() == 2,
        "{logout}"
    );
}

/// With bearer auth off: no bearer scheme, no `X-Auth-Token` header, and a
/// single security alternative on secured operations.
#[test]
fn bearer_auth_off_drops_the_scheme_and_the_header() {
    let doc = config().with_bearer_auth(false).openapi().to_json();
    let schemes = doc["components"]["securitySchemes"].as_object().unwrap();
    assert!(!schemes.contains_key("bearer"), "{schemes:?}");
    assert!(schemes.contains_key("session_cookie"), "{schemes:?}");

    let login = &doc["paths"]["/login/password"]["post"];
    assert!(
        login["responses"]["200"]["headers"]
            .get("X-Auth-Token")
            .is_none(),
        "{login}"
    );

    let logout = &doc["paths"]["/logout"]["post"];
    assert_eq!(logout["security"].as_array().unwrap().len(), 1, "{logout}");
}

/// The default-feature document is pinned. `UPDATE_SNAPSHOTS=1` rewrites it.
///
/// The file it compares against was generated with every feature on, so a
/// reduced-feature run would document fewer operations and fail: the test
/// only exists when the whole surface is compiled in.
#[cfg(all(
    feature = "oauth",
    feature = "webauthn",
    feature = "totp",
    feature = "sms",
    feature = "pages"
))]
#[test]
fn snapshot() {
    let json = serde_json::to_string_pretty(&config().openapi().to_json()).unwrap() + "\n";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots/openapi.json");
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(path, &json).unwrap();
    }
    let expected = std::fs::read_to_string(path).expect("run with UPDATE_SNAPSHOTS=1 once");
    assert_eq!(
        json, expected,
        "document changed; review the diff and rerun with UPDATE_SNAPSHOTS=1"
    );
}

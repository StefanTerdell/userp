//! Integration test for OIDC id_token validation against a live Keycloak.
//!
//! Requires the dev stack to be running:
//!   docker compose -f dev/compose.yaml up -d
//!
//! The test fetches a real id_token from Keycloak via the direct-grant flow,
//! then checks that authery's validation accepts it and rejects tampered or
//! wrong-audience/issuer tokens. If Keycloak is not reachable the test skips
//! (returns early) rather than failing, so `cargo test` stays green offline.

use authery::oauth::client::validate_oidc_id_token;
use authery::reexports::jsonwebtoken::jwk::JwkSet;
use serde_json::Value;

const ISSUER: &str = "http://localhost:8080/realms/authery";
const CLIENT_ID: &str = "authery-example";
const CLIENT_SECRET: &str = "authery-secret";

async fn keycloak_up() -> bool {
    reqwest::get(format!("{ISSUER}/.well-known/openid-configuration"))
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

async fn fetch_id_token() -> String {
    let res = reqwest::Client::new()
        .post(format!("{ISSUER}/protocol/openid-connect/token"))
        .form(&[
            ("grant_type", "password"),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("username", "testuser"),
            ("password", "testpass"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token request")
        .json::<Value>()
        .await
        .expect("token json");

    res["id_token"]
        .as_str()
        .expect("id_token present")
        .to_owned()
}

async fn fetch_jwks() -> JwkSet {
    let discovery = reqwest::get(format!("{ISSUER}/.well-known/openid-configuration"))
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let jwks_uri = discovery["jwks_uri"].as_str().unwrap();
    reqwest::get(jwks_uri)
        .await
        .unwrap()
        .json::<JwkSet>()
        .await
        .unwrap()
}

#[tokio::test]
async fn validates_real_keycloak_id_token() {
    if !keycloak_up().await {
        eprintln!("skipping: Keycloak not reachable at {ISSUER}");
        return;
    }

    let id_token = fetch_id_token().await;
    let jwks = fetch_jwks().await;

    // A genuine token validates and yields a subject.
    let sub = validate_oidc_id_token(&id_token, &jwks, ISSUER, CLIENT_ID, None)
        .expect("valid token accepted");
    assert!(!sub.is_empty());

    // Wrong audience is rejected.
    assert!(
        validate_oidc_id_token(&id_token, &jwks, ISSUER, "someone-else", None).is_err(),
        "wrong audience must be rejected"
    );

    // Wrong issuer is rejected.
    assert!(
        validate_oidc_id_token(&id_token, &jwks, "https://evil.example", CLIENT_ID, None).is_err(),
        "wrong issuer must be rejected"
    );

    // A mismatched nonce is rejected.
    assert!(
        validate_oidc_id_token(&id_token, &jwks, ISSUER, CLIENT_ID, Some("not-the-nonce")).is_err(),
        "mismatched nonce must be rejected"
    );

    // A tampered signature is rejected.
    let mut parts: Vec<&str> = id_token.split('.').collect();
    parts[2] = "AAAA";
    let tampered = parts.join(".");
    assert!(
        validate_oidc_id_token(&tampered, &jwks, ISSUER, CLIENT_ID, None).is_err(),
        "tampered signature must be rejected"
    );
}

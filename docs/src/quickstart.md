# Quickstart

Add authery with the features you want (see [Features](features.md)):

```toml
[dependencies]
authery = { version = "0.1", features = ["axum", "pages", "otp", "webauthn", "mfa"] }
```

Implement [`AutheryStore`](store.md) for your storage, then configure and
mount the router:

```rust,ignore
use authery::prelude::*;

#[derive(Clone, axum_macros::FromRef)]
struct AppState {
    store: MyStore,
    auth: AutheryConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = url::Url::parse("https://my-app.example")?;

    let auth = AutheryConfig::new(
        std::env::var("AUTH_KEY")?, // cookie encryption key, >= 64 bytes
        Routes::default(),          // or .with_prefix("/auth")
        PasswordConfig::new(),
        EmailConfig::new(
            base_url.clone(),
            SmtpSettings::new("smtps://user:pass@smtp.example.com:465", "auth@my-app.example"),
        ),
        OAuthConfig::new(base_url.clone())
            .with_client(GitHubOAuthProvider::new(id, secret))
            .with_client(GoogleOAuthProvider::new(id, secret)),
        WebauthnConfig::new(base_url, "My app")?,
    )?;

    let app = axum::Router::new()
        .merge(auth.router::<MyStore, AppState>())
        .route("/", axum::routing::get(index))
        .with_state(AppState { store: MyStore::new(), auth });

    // serve as usual
    Ok(())
}
```

The router now serves `/login`, `/signup`, `/user` (account management),
`/logout` (POST), password reset, email verification, the oauth callbacks,
passkey ceremonies and the MFA page.

## Gating your own routes

Extract the auth service in any handler and ask for the session or user:

```rust,ignore
async fn protected(auth: Authery<MyStore>) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await? else {
        return Redirect::to("/login?next=%2Fprotected").into_response();
    };
    // ...
}
```

Cookies set during a request propagate automatically — the built-in router
installs a tower layer for it. If you route authery handlers through your own
router instead, wrap it with `with_cookie_layer` (exported in the prelude) or
return the auth service as part of the response.

## Local development

The repo ships a compose file with Keycloak (a real OIDC provider with a
preconfigured `authery` realm) and Mailhog (catches all outgoing email):

```sh
docker compose -f dev/compose.yaml up -d
# Mailhog UI:  http://localhost:8025
# Keycloak UI: http://localhost:8080 (admin/admin)
```

`SmtpSettings::new("smtp://localhost:1025", "auth@example.com")` points email
at Mailhog. See `examples/memory-store` for a complete runnable app.

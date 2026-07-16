# Authery

Batteries-included authentication for Axum: sessions, passwords, email links
and one-time codes, OAuth2/OIDC, passkeys, and MFA — behind one composable
crate with a ready-made router and replaceable pages, on top of whatever
storage you bring.

> **Status**: pre-release, APIs still moving. The `authery` branch is the
> active rewrite of the earlier `userp` crate.

## What you get

- **Session handling** — encrypted `HttpOnly` cookies, absolute expiry,
  optional per-user concurrent-session caps, server-side logout.
- **Login methods**, each behind a feature flag:
  - `password` — argon2 hashing (pluggable hasher), enumeration-resistant login
  - `email` — magic links: signup, login, verification, password reset
  - `otp` — six-digit codes over email instead of links
  - `oauth` — OAuth2/OIDC with PKCE, validated id_tokens (JWKS + nonce),
    token refresh and account linking; 11 built-in providers plus fully
    custom ones, resolvable at runtime for multi-tenant setups
  - `webauthn` — passkeys: usernameless login and account-page registration
  - `mfa` — policy-driven second factors (passkey or emailed code) on top of
    any first factor
- **An Axum router** serving all of it, with templated pages (`pages`
  feature) you can restyle or replace wholesale via a `Pages` trait — or skip
  the router and call the core flows from your own handlers.
- **Your storage** — implement the `AutheryStore` trait over any backend;
  entities are trait-defined with generic ID types, so your existing models
  and id scheme stay yours. A rate-limiter hook lets you plug your own
  counters in front of abusable operations.

## Quickstart

```rust,ignore
use authery::prelude::*;

#[derive(Clone, axum_macros::FromRef)]
struct AppState {
    store: MyStore, // your AutheryStore implementation
    auth: AutheryConfig,
}

let auth = AutheryConfig::new(
    std::env::var("AUTH_KEY")?, // >= 64 bytes, secret
    Routes::default(),
    PasswordConfig::new(),
    EmailConfig::new(base_url.clone(), SmtpSettings::new(smtp_url, from)),
    OAuthConfig::new(base_url.clone())
        .with_client(GitHubOAuthProvider::new(client_id, client_secret)),
    WebauthnConfig::new(base_url, "My app")?,
)?;

let app = axum::Router::new()
    .merge(auth.router::<MyStore, AppState>())
    .with_state(AppState { store, auth });
```

That's a working `/login`, `/signup`, `/user`, password reset, magic links,
GitHub SSO and passkeys. See `examples/memory-store` for the full picture —
including multi-tenant per-org SSO built at app level on the provider
resolver — and `examples/memory-store-password-only-no-templates` for the
minimal, bring-your-own-pages setup.

## Development

```sh
docker compose -f dev/compose.yaml up -d   # Keycloak (OIDC) + Mailhog (SMTP)
cargo test -p authery --no-default-features \
  --features password,email,otp,mfa,user   # core flow tests
cargo test -p authery                      # + live Keycloak OIDC validation when up
mdbook serve docs                          # the book
```

`dev/PROVIDERS.md` lists the external OAuth providers and the env vars the
example picks them up from.

## License

ISC

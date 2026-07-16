# OAuth2 & OIDC

All authorization-code flows send PKCE (S256), keep their state in a
single-use encrypted cookie, and — for OIDC providers — validate the returned
id_token: signature against the issuer's JWKS (discovered from the issuer
URL), `iss`, `aud`, `exp`, and a per-request `nonce`. The validated claims
are what your store receives as `provider_user_raw`.

## Built-in providers

`GitHub`, `GitLab` (plain + `new_oidc` with id_token validation), `Google`,
`Spotify`, `Microsoft`, `Discord`, `Facebook`, `Twitch`, `Slack`, `LinkedIn`,
`X` — each a one-liner:

```rust,ignore
OAuthConfig::new(base_url)
    .with_client(DiscordOAuthProvider::new(client_id, client_secret))
```

## Custom providers

- `OAuthOidcProvider::new(name, display, id, secret, issuer, auth_url, token_url, scopes)`
  — any spec-compliant OIDC provider, with full id_token validation.
- `OAuthCustomProvider::new_with_callback(...)` — plain OAuth2 with a closure
  that turns an access token into a provider user (see the built-in
  providers' sources for the pattern).

## Flows

Beyond login and signup, the `user` feature adds **linking** (attach another
provider to the logged-in account) and **refresh** (server-side token refresh
with ownership checks) — the account page exposes both. Access and refresh
tokens live in your store, so your app can use them for API integrations.

## Runtime resolution (multi-tenancy)

Providers don't have to be fixed at startup. Register a resolver and start
flows with a context:

```rust,ignore
OAuthConfig::new(base_url).with_provider_resolver(MyResolver { db })
// ...
auth.oauth_login_init_with_context("tenant-slug".into(), "okta", next).await?
```

The opaque `context` string rides the encrypted state cookie; both init and
callback resolve the provider through your resolver, and the store receives
the context on the resulting token. This is the primitive for per-tenant SSO
— the [organizations chapter](../organizations.md) builds on it.

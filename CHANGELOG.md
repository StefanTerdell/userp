# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The initial release of `authery`, the continuation of the earlier `userp`
crate. Everything below is new relative to userp 0.0.x:

### Added

- Single-crate design with feature flags: `user`, `password`, `email`,
  `oauth`, `webauthn`, `totp`, `sms`, `mfa`, `pages`, `axum`.
- Generic entity ids: every entity is a trait with associated id types.
- Passkeys (WebAuthn): usernameless login + account-page registration.
- MFA policy layer with passkey, authenticator-app (TOTP), emailed-code,
  texted-code and single-use recovery-code second factors.
- Emailed one-time codes (part of `email`, toggleable by config) and
  texted codes (`sms`) with five built-in
  SMS gateway senders and a pluggable `SmsSender`/`CodeGenerator`.
- OIDC id_token validation (JWKS signature, iss/aud/exp/nonce) and PKCE on
  every flow; 11 built-in OAuth providers plus custom/OIDC constructors.
- Runtime provider resolution (`OAuthProviderResolver`) with an app-chosen
  context that reaches the store - the multi-tenant SSO primitive.
- A single OAuth callback route; flow and provider ride the encrypted state
  cookie, keyed per flow so concurrent logins don't collide.
- Opt-in bearer-token session mode with an optional token prefix.
- `StoreError`: store failures render as a generic 500 unless the store
  opts in with `PublicError`; the error page and JSON body never carry the
  raw error.
- JSON transport: `Accept: application/json` turns flow redirects into
  `200 {"next"}` / `422 {"error","next"}`, and every flow endpoint accepts
  its fields as JSON or form-encoded bodies (`FormOrJson` extractor).
- Rate-limiter hook, auth-event hook (tracing by default), customizable
  email/SMS copy, replaceable pages, per-route overrides.
- Redesigned bundled pages: a single-column auth screen grammar with a
  method switch on login/signup, and a two-column account page (Source
  Serif 4 + Material Symbols via Bunny Fonts, `brand.html` wordmark slot).
- Delivery failures (SMTP, SMS gateway) surface to the end user as a generic
  "could not send" message; the underlying error is reported through the
  `AuthEvent::DeliveryFailed` event instead of the redirect query string.
- Session lifetime, per-user concurrent-session caps, server-side eviction.
- Sessions record user agent and client address (`SessionMeta`); "sign out
  everywhere else" on the account page; a password reset ends every session.
- Trusted devices: completing MFA can remember the browser for
  `MfaPolicy::trusted_device_lifetime`, recorded as
  `LoginMethod::TrustedDevice`.
- Passkeys are stored as `PasskeyRecord`s with an optional name, creation and
  last-used times.
- Password requirements as a regex (`PasswordConfig::pattern`, default at
  least 8 characters) checked on signup, set and reset and exposed to the
  pages as the input's `pattern` attribute.
- Cookie names (`CookieNames`) and the recovery-code batch size are
  configurable.
- Dedicated pages for "check your inbox", expired links, and rate-limit
  refusals (`/email/sent`, `/email/expired`, `/paused`).
- Optional `OAuthToken::get_scopes`/`get_created` and
  `UserEmail::get_verified_at` for the account page.
- Reference stores: Postgres (sqlx) and in-memory, feature-gated like the
  store trait itself.
- `openapi` feature: `auth.openapi()` returns a serde OpenAPI 3.1 document of
  every mounted route; `convert()` loads it into utoipa's or aide's types.
  Page-class routes (the HTML GETs and the two POSTs that render a page)
  are excluded unless `with_pages(true)` asks for them.
- `aide` feature: `auth.api_router()` registers every route through aide's
  typed routing.

### Changed

- Store error types implement `StoreError` instead of `IntoResponse`.
- Handlers return `Result<Response, StoreFailure<E>>`, and `error_redirect`
  refuses to stringify an error that could be a store failure: it diverts
  one into a `StoreFailure` instead, so no store's `Display` can reach a
  `?error=` redirect.
- Endpoints that need a session answer `401 {"error": "Not logged in."}`
  instead of an empty `401`; a rejected passkey registration answers `401`
  like the other two ceremonies.
- `with_cookie_layer` takes the pages renderer and login route (with `pages`).

[Unreleased]: https://github.com/StefanTerdell/userp/commits/authery

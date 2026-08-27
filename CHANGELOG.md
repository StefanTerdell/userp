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
- Rate-limiter hook, auth-event hook (tracing by default), customizable
  email/SMS copy, replaceable pages, per-route overrides.
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

[Unreleased]: https://github.com/StefanTerdell/userp/commits/authery

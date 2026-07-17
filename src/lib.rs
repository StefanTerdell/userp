//! # Summary
//!
//! Batteries-included authentication for [Axum](https://github.com/tokio-rs/axum);
//! brings the auth, you bring the storage!
//!
//! - Sessions, passwords, magic links, emailed and texted one-time codes,
//!   OAuth2/OIDC, passkeys, authenticator apps and an MFA policy layer - all
//!   behind individual feature flags.
//! - A ready-made router with login/signup/account pages you can restyle or
//!   replace, plus all the action, callback and ceremony endpoints.
//! - No database, no migrations, no imposed schema: you implement one store
//!   trait over your own models and id types, and authery calls it.
//! - Hardened by default: argon2, PKCE, validated id_tokens, encrypted
//!   single-use state cookies, enumeration-resistant errors, session expiry
//!   and rotation-free opaque bearer tokens.
//!
//! _Status: pre-release; APIs still moving._
//!
//! # Usage
//!
//! ## Basic example
//!
//! Enable the features you want (see the table below):
//!
//! ```toml
//! [dependencies]
//! authery = { version = "0.1", features = ["axum", "pages", "otp", "webauthn", "mfa"] }
//! ```
//!
//! Implement [`AutheryStore`](store::AutheryStore) for your storage (see
//! *The store* below), then configure and mount the router:
//!
//! ```rust,ignore
//! use authery::prelude::*;
//!
//! #[derive(Clone, axum_macros::FromRef)]
//! struct AppState {
//!     store: MyStore,
//!     auth: AutheryConfig,
//! }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let base_url = url::Url::parse("https://my-app.example")?;
//!
//!     let auth = AutheryConfig::new(
//!         std::env::var("AUTH_KEY")?, // cookie encryption key, >= 64 bytes
//!         Routes::default(),          // or .with_prefix("/auth")
//!         PasswordConfig::new(),
//!         EmailConfig::new(
//!             base_url.clone(),
//!             SmtpSettings::new("smtps://user:pass@smtp.example.com:465", "auth@my-app.example"),
//!         ),
//!         OAuthConfig::new(base_url.clone())
//!             .with_client(GitHubOAuthProvider::new(github_id, github_secret)),
//!         WebauthnConfig::new(base_url, "My app")?,
//!     )?;
//!
//!     let app = axum::Router::new()
//!         .merge(auth.router::<MyStore, AppState>())
//!         .route("/", axum::routing::get(index))
//!         .with_state(AppState { store: MyStore::new(), auth });
//!
//!     // serve as usual
//!     Ok(())
//! }
//! ```
//!
//! The router now serves `/login`, `/signup`, `/user` (account management),
//! `/logout` (POST), password reset, email verification, the oauth
//! callbacks, passkey ceremonies and the MFA page. `AutheryConfig::new`
//! takes one config argument per enabled method feature, so forgetting one
//! is a compile error rather than a runtime surprise.
//!
//! ## Gating your own routes
//!
//! Extract the auth service in any handler and ask for the session or user:
//!
//! ```rust,ignore
//! async fn protected(auth: Authery<MyStore>) -> impl IntoResponse {
//!     let Some((user, session)) = auth.user_session().await? else {
//!         return Redirect::to("/login?next=%2Fprotected").into_response();
//!     };
//!     // ...
//! }
//! ```
//!
//! Every login method produces a session whose
//! [`LoginMethod`](models::LoginMethod) records how it was created
//! (including both factors for MFA sessions), and
//! [`LoginMethodRules`](models::LoginMethodRules) turns that into policy for
//! sensitive routes:
//!
//! ```rust,ignore
//! let rules = LoginMethodRules { require_mfa: true, ..Default::default() };
//! if !rules.satisfies(&session.get_method()) {
//!     // send them off to set up or complete MFA
//! }
//! ```
//!
//! Cookies set during a request propagate automatically - the built-in
//! router installs a tower layer for it. If you route authery handlers
//! through your own router instead, wrap it with `with_cookie_layer`
//! (exported in the prelude) or return the auth service as part of the
//! response.
//!
//! # Feature flags
//!
//! | Feature | What it enables | Store additions |
//! |---|---|---|
//! | `user` | Account management: session listing, email/password management, account deletion | user-scoped queries & mutations |
//! | `password` | Password login/signup, pluggable hasher | password-id lookup & user creation |
//! | `email` | Magic links: login, signup, verification, password reset (with `password`); async SMTP | user-email entities, single-use challenges |
//! | `otp` | One-time emailed codes; standalone, or alongside `email` links | user-email entities, challenges (shared with `email`) |
//! | `sms` | Texted six-digit codes: login, signup, MFA; five ready-made gateway senders or bring-your-own `SmsSender` | user-phone entities (challenges shared with `email`) |
//! | `oauth` | OAuth2/OIDC: login, signup, linking, refresh; PKCE + validated id_tokens; runtime provider resolution | oauth token entities & lookups |
//! | `webauthn` | Passkeys: usernameless login, account-page registration | passkey blobs keyed by credential id |
//! | `totp` | Authenticator-app codes (RFC 6238) as a second factor, QR enrollment | one TOTP credential per user |
//! | `mfa` | Second-factor policy over any first factor; single-use recovery codes | recovery-code hashes |
//! | `pages` | Bundled Askama pages + the `Pages` replacement trait | - |
//! | `axum` | The extractor, router and cookie layer | - |
//!
//! Default: `user`, `email`, `password`, `oauth`.
//!
//! # The store
//!
//! Authery's only persistence interface is the
//! [`AutheryStore`](store::AutheryStore) trait. You implement it over your
//! database; authery never sees connection strings or SQL, and the trait
//! only asks for the methods your enabled features use. Each entity is a
//! trait your concrete types implement, with associated id types satisfying
//! [`Id`](models::Id) (`Clone + Display + FromStr + PartialEq + ...` - Uuid
//! works out of the box, and so do newtypes):
//!
//! ```rust,ignore
//! impl LoginSession for MySession {
//!     type Id = Uuid;
//!     type UserId = Uuid;
//!     fn get_id(&self) -> Uuid { self.id }
//!     fn get_user_id(&self) -> Uuid { self.user_id }
//!     fn get_method(&self) -> LoginMethod { self.method.clone() }
//!     fn get_expires(&self) -> DateTime<Utc> { self.expires }
//! }
//! ```
//!
//! Your types can carry any extra fields your app needs - authery only calls
//! the getters. A few store methods carry security-relevant contracts:
//!
//! - `consume_challenge` must fetch **and delete** - challenges and codes
//!   are single-use.
//! - `create_session` ids act as bearer tokens: generate them with a CSPRNG
//!   (`Id::new_random` on Uuid does).
//! - `delete_session` / `delete_oauth_token` / `delete_passkey` are scoped
//!   by user id - verify ownership.
//!
//! Because the store is your code, it observes every user creation, login
//! and token exchange - that's where app-level side effects (provisioning,
//! tenant membership, analytics) belong, without authery needing a hook for
//! each.
//!
//! # Login methods
//!
//! ## Passwords (`password`)
//!
//! [`PasswordConfig::new()`](password::PasswordConfig) gives argon2 hashing
//! on a blocking thread pool; swap the hasher with `.with_hasher(...)`.
//! Login is enumeration-resistant: unknown users and wrong passwords return
//! the same error, and comparable hash work is burned on the miss paths so
//! timing doesn't reveal account existence.
//!
//! With `email` also enabled, password reset works over emailed links
//! (`.with_allow_reset(...)`, verified-only by default). Reset links create
//! single-use, purpose-bound sessions that cannot access anything but the
//! reset flow.
//!
//! ## Email links & one-time codes (`email`, `otp`)
//!
//! Two independent features over the same email infrastructure: `email` is
//! magic links (signup/login links, address verification, password-reset
//! delivery), `otp` is one-time codes - enable either or both. SMTP is
//! async (lettre) and configured with a single URL:
//!
//! ```text
//! smtps://user:pass@smtp.example.com:465                implicit TLS
//! smtp://user:pass@smtp.example.com:587?tls=required    STARTTLS
//! smtp://localhost:1025                                 plain, for Mailhog etc.
//! ```
//!
//! Every email and text authery sends is composable copy: implement
//! `EmailMessages` / `SmsMessages` (each method has an English default, so
//! override selectively) and register with `.with_messages(...)` on the
//! channel config - that's the branding/localization hook.
//!
//! The `otp` feature sends one-time codes instead of links - same challenge
//! store, different UX. Codes are namespaced per address, single-use,
//! short-lived and rate-limited through your `RateLimiter`. The generator is
//! pluggable per channel (`CodeGenerator` via
//! `with_code_generator` on `EmailConfig`/`SmsConfig`); the default is
//! CSPRNG-backed six digits, and the bundled code-entry inputs adapt to a
//! custom generator through its input-mode and length hints. Remember that
//! any typeable code is guessable: the load-bearing control is the rate
//! limiter, not code length.
//!
//! ## OAuth2 & OIDC (`oauth`)
//!
//! All authorization-code flows send PKCE (S256) and keep their state in
//! single-use encrypted cookies keyed per flow (concurrent login tabs don't
//! clobber each other). OIDC providers get full id_token validation:
//! signature against the issuer's JWKS, `iss`, `aud`, `exp` and a
//! per-request `nonce`. The validated claims are what your store receives.
//!
//! Built-in providers, each a one-liner: GitHub, GitLab, Google, Spotify,
//! Microsoft, Discord, Facebook, Twitch, Slack, LinkedIn and X. For anything
//! else, `OAuthOidcProvider`
//! covers any spec-compliant OIDC issuer with full validation, and
//! `OAuthCustomProvider` covers plain OAuth2 with a callback that turns an
//! access token into a provider user.
//!
//! Beyond login and signup, the `user` feature adds **linking** (attach
//! another provider to the logged-in account) and **refresh** (server-side,
//! ownership-checked token refresh). Access and refresh tokens live in your
//! store, so your app can use them for API integrations.
//!
//! Every flow returns to a single callback route (default
//! `/oauth/callback`): the flow type, provider and PKCE/nonce material ride
//! the encrypted state cookie, so no per-provider or per-flow path segments
//! are needed. Register `{base_url}/oauth/callback` as the redirect URI with
//! each provider.
//!
//! Providers don't have to be fixed at startup - see *Multi-tenancy* below.
//!
//! ## Passkeys (`webauthn`)
//!
//! Two ceremonies wired end to end (JSON endpoints + inline page scripts):
//! registration from the account page (resident keys required) and
//! usernameless login - authery resolves the credential and user by
//! credential id, so your user-id type is never embedded in authenticator
//! hardware. Credentials are stored as opaque `Passkey` blobs; signature
//! counters and backup state are persisted after each login for clone
//! detection. Ceremony state rides the encrypted cookie jar, keyed per
//! ceremony.
//!
//! ## Authenticator apps (`totp`)
//!
//! RFC 6238 codes (SHA-1, six digits, 30s steps, ±1 step skew - what
//! authenticator apps actually support). Enrollment is two-step so a typo'd
//! setup can't lock anyone out: `totp_enroll_start` returns an `otpauth://`
//! URL and a ready-to-embed QR PNG, and the secret only counts as a factor
//! after `totp_enroll_confirm` verifies a live code. Each successful
//! verification records the matched time step and rejects codes at or before
//! it - a captured code can't be replayed within its window.
//!
//! ## Texted codes (`sms`)
//!
//! The email OTP flow for phone numbers: signup and login by texted
//! six-digit code, plus a texted second factor for MFA. Authery is
//! gateway-neutral: ready-made Twilio / Vonage / MessageBird / Telnyx /
//! 46elks senders are included, and anything implementing the one-method
//! `SmsSender` trait works. Store numbers in E.164 form; authery compares
//! them as opaque strings. Mind the factor's limits: SIM-swap attacks are
//! routine enough that NIST discourages SMS for high-value accounts.
//!
//! ## Multi-factor authentication (`mfa`)
//!
//! A policy layer over the other methods.
//! `MfaPolicy` names the first factors that must be backed
//! by a second one (default: passwords only). When such a login succeeds
//! *and the user has a factor registered*, the session is **pending** -
//! treated as logged-out everywhere except the completion flow, which offers
//! a passkey ceremony, an authenticator code, a one-time code sent to the
//! user's **own verified** address or number (never one supplied in the
//! request, and never the channel the first factor already proved), or a
//! single-use recovery code. Completing it mints a session whose method
//! records both factors.
//!
//! Recovery codes are the lockout escape hatch: the account page generates a
//! batch of ten (shown exactly once; only SHA-256 hashes reach your store),
//! each usable a single time. Generating a new batch replaces the old one.
//!
//! Users without a registered factor log in normally - hard-requiring MFA at
//! login would lock out every fresh signup. Apps wanting mandatory MFA gate
//! their routes with `LoginMethodRules { require_mfa: true, .. }` instead
//! (single-factor passkeys count: possession + user verification).
//!
//! # JSON clients
//!
//! The flows speak browser by default: outcomes are redirects, with errors
//! riding `?error=` query params. Send `Accept: application/json` and the
//! transport layer translates every flow redirect uniformly instead:
//!
//! - `200 {"next": "..."}` on success (plus `"message"` when one rides along)
//! - `422 {"error": "...", "next": "..."}` on flow errors
//!
//! Cookies and the `X-Auth-Token` header behave identically, so a mobile
//! client logs in by POSTing the same form with the JSON accept header,
//! keeps the token, and sends it as `Authorization: Bearer` from then on.
//!
//! # Sessions & bearer tokens
//!
//! Sessions live in your store with CSPRNG ids, absolute expiry
//! (`with_session_lifetime`, default 30 days, server-side eviction), an
//! optional per-user concurrency cap (`with_max_concurrent_sessions`, oldest
//! evicted first), and an optional idle timeout (`with_idle_timeout` -
//! requires the store to track activity via `LoginSession::get_last_seen`
//! and `touch_session`; touches are throttled to once a minute). Logout is
//! POST-only.
//!
//! Rotating the cookie-encryption key doesn't have to be a mass logout:
//! `.with_previous_keys([old_key])` accepts cookies sealed under previous
//! keys during a grace window and re-encrypts them with the current key on
//! the next response. Writes always use the current key.
//!
//! For API and mobile clients, `.with_bearer_auth(true)` accepts
//! `Authorization: Bearer {token}` as an alternative to the session cookie
//! and exposes fresh session ids via an `X-Auth-Token` response header on
//! login. Tokens are opaque session ids - server-side, revocable, and
//! subject to the same expiry and caps as cookie sessions. There is
//! deliberately no stateless JWT mode. An optional
//! `.with_bearer_token_prefix("myapp_")` makes tokens recognizable to humans
//! and secret scanners, GitHub-`ghp_` style.
//!
//! # Pages
//!
//! The `pages` feature bundles plain Askama templates for login, signup, the
//! account page, password reset, code entry and the MFA picker. Restyle
//! them, or implement the `Pages` trait to render the same
//! view-models with your own templating - you keep the router and flows
//! while owning the markup. Or skip `pages` entirely and the router serves
//! only the action/callback endpoints.
//!
//! # Routes
//!
//! Every path authery serves or links to lives in the
//! [`Routes`](routes::Routes) struct handed to `AutheryConfig::new`, and all
//! of them are overridable - prefix everything, or reshape individual
//! routes with plain struct syntax:
//!
//! ```rust,ignore
//! // Everything under /auth:
//! let routes = Routes::default().with_prefix("/auth");
//!
//! // ...or override specific paths:
//! let routes = Routes {
//!     oauth: OAuthRoutes {
//!         callback: "/auth/callback",
//!         ..Default::default()
//!     },
//!     pages: PageRoutes {
//!         login: "/signin",
//!         ..Default::default()
//!     },
//!     ..Default::default()
//! };
//! ```
//!
//! # Observability
//!
//! Authery logs every auth-relevant event through `tracing` out of the
//! box: successful logins at `info`; failed passwords, rejected codes,
//! failed OAuth callbacks and rate-limit hits at `warn`. To do more than
//! log (alert, count, lock accounts), implement the one-method
//! `AuthEventHandler` and register it with `.with_event_handler(...)` -
//! these are exactly the failures your store never sees.
//!
//! # Rate limiting
//!
//! Authery calls your [`RateLimiter`](ratelimit::RateLimiter) before
//! abusable operations - password attempts, email/SMS sends, code
//! verification attempts - keyed on the identifier in question. IP-keyed
//! limiting is best done in a tower layer around the router; the hook covers
//! what only authery can see. Be strict on code attempts (six digits are
//! guessable) and SMS sends (every text costs money).
//!
//! # Multi-tenancy
//!
//! Authery deliberately has no organizations feature - members, roles,
//! invites and admin pages are app domain. What your app can't easily build
//! alone is the auth plumbing for per-tenant SSO against providers unknown
//! until request time, so that's the primitive authery provides:
//!
//! 1. Register an [`OAuthProviderResolver`](oauth::OAuthProviderResolver)
//!    that builds providers from *your* tables, keyed by an opaque context
//!    string (e.g. the tenant slug).
//! 2. Start flows with `oauth_login_init_with_context(context, provider,
//!    next)` - the context rides the encrypted state cookie and both init
//!    and callback resolve through your resolver.
//! 3. Your store receives the context alongside the **validated** claims on
//!    the resulting token - that's your membership hook.
//!
//! The `memory-store` example contains a complete org setup built this way,
//! verified against Keycloak.
//!
//! # Security
//!
//! Argon2 off the async runtime; enumeration-resistant login; encrypted,
//! authenticated, `HttpOnly`, `SameSite=Lax` cookies (`Secure` unless
//! `.with_https_only(false)`; the encryption key is length-checked at config
//! time); PKCE everywhere; validated id_tokens; single-use, per-flow-keyed
//! state cookies; purpose-bound sessions that can't act as logins;
//! open-redirect protection on every `next` parameter.
//!
//! Your side of the deal: serve over HTTPS, wire the rate limiter, treat the
//! cookie key as a secret, and honor the store contracts above.
//! `SECURITY_REVIEW.md` in the repo tracks the standing review, fixes and
//! known gaps.
//!
//! # Local development
//!
//! The repo ships a compose file with Keycloak (a real OIDC provider with a
//! preconfigured realm), Mailhog (catches all outgoing email) and Postgres:
//!
//! ```sh
//! docker compose -f dev/compose.yaml up -d
//! # Mailhog UI:  http://localhost:8025
//! # Keycloak UI: http://localhost:8080 (admin/admin)
//! ```
//!
//! The examples split into store libraries and feature-focused apps that
//! share them. Each app is its own workspace, so its IDE view resolves
//! exactly the features it enables - run apps with `cargo run` inside
//! `examples/<name>`:
//!
//! - `examples/postgres-store` - **the reference store**: a complete,
//!   feature-gated `AutheryStore` over sqlx/Postgres, schema included. Start
//!   here when implementing your own.
//! - `examples/memory-store` - the same store shape over in-memory maps.
//! - `examples/full` - every feature at once, over either store
//!   (`DATABASE_URL` picks Postgres, its absence the memory store).
//! - `examples/multi-tenant` - per-org SSO on the provider resolver, against
//!   the dev Keycloak.
//! - `examples/email-otp` - passwordless magic links + one-time codes.
//! - `examples/password-only` - the minimal bring-your-own-pages setup.
//!
//! Everything user-visible is exported through [`prelude`].

#![cfg_attr(not(feature = "default"), allow(unused))]

#[cfg(any(feature = "otp", feature = "sms"))]
pub mod codes;
pub mod config;
pub mod constants;
pub mod core;
pub mod events;
#[cfg(feature = "mfa")]
pub mod mfa;
pub mod models;
pub mod prelude;
pub mod ratelimit;
pub mod reexports;
pub mod routes;
#[cfg(feature = "sms")]
pub mod sms;
pub mod store;
#[cfg(feature = "totp")]
pub mod totp;
#[cfg(feature = "webauthn")]
pub mod webauthn;

#[cfg(any(feature = "email", feature = "otp"))]
pub mod email;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "password")]
pub mod password;

#[cfg(feature = "pages")]
pub mod pages;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "axum")]
pub use axum::AxumAuthery as Authery;
#[cfg(not(feature = "axum"))]
pub use core::CoreAuthery as Authery;

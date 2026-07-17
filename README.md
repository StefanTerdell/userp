# Authery

[![Crates.io Version](https://img.shields.io/crates/v/authery.svg)](https://crates.io/crates/authery)
[![docs.rs](https://img.shields.io/docsrs/authery)](https://docs.rs/authery)
[![CI](https://github.com/StefanTerdell/userp/actions/workflows/ci.yml/badge.svg)](https://github.com/StefanTerdell/userp/actions/workflows/ci.yml)

<!-- cargo-rdme start -->

## Summary

Batteries-included authentication for [Axum](https://github.com/tokio-rs/axum);
brings the auth, you bring the storage!

- Sessions, passwords, magic links, emailed and texted one-time codes,
  OAuth2/OIDC, passkeys, authenticator apps and an MFA policy layer - all
  behind individual feature flags.
- A ready-made router with login/signup/account pages you can restyle or
  replace, plus all the action, callback and ceremony endpoints.
- No database, no migrations, no imposed schema: you implement one store
  trait over your own models and id types, and authery calls it.
- Hardened by default: argon2, PKCE, validated id_tokens, encrypted
  single-use state cookies, enumeration-resistant errors, session expiry
  and rotation-free opaque bearer tokens.

_Status: pre-release; APIs still moving._

## Usage

### Basic example

Enable the features you want (see the table below):

```toml
[dependencies]
authery = { version = "0.1", features = ["axum", "pages", "otp", "webauthn", "mfa"] }
```

Implement [`AutheryStore`](https://docs.rs/authery/latest/authery/store/trait.AutheryStore.html) for your storage (see
*The store* below), then configure and mount the router:

```rust
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
            .with_client(GitHubOAuthProvider::new(github_id, github_secret)),
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
`/logout` (POST), password reset, email verification, the oauth
callbacks, passkey ceremonies and the MFA page. `AutheryConfig::new`
takes one config argument per enabled method feature, so forgetting one
is a compile error rather than a runtime surprise.

### Gating your own routes

Extract the auth service in any handler and ask for the session or user:

```rust
async fn protected(auth: Authery<MyStore>) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await? else {
        return Redirect::to("/login?next=%2Fprotected").into_response();
    };
    // ...
}
```

Every login method produces a session whose
[`LoginMethod`](https://docs.rs/authery/latest/authery/models/enum.LoginMethod.html) records how it was created
(including both factors for MFA sessions), and
[`LoginMethodRules`](https://docs.rs/authery/latest/authery/models/struct.LoginMethodRules.html) turns that into policy for
sensitive routes:

```rust
let rules = LoginMethodRules { require_mfa: true, ..Default::default() };
if !rules.satisfies(&session.get_method()) {
    // send them off to set up or complete MFA
}
```

Cookies set during a request propagate automatically - the built-in
router installs a tower layer for it. If you route authery handlers
through your own router instead, wrap it with `with_cookie_layer`
(exported in the prelude) or return the auth service as part of the
response.

## Feature flags

| Feature | What it enables | Store additions |
|---|---|---|
| `user` | Account management: session listing, email/password management, account deletion | user-scoped queries & mutations |
| `password` | Password login/signup, pluggable hasher | password-id lookup & user creation |
| `email` | Magic links: login, signup, verification, password reset (with `password`); async SMTP | user-email entities, single-use challenges |
| `otp` | Six-digit emailed codes as an alternative to links (implies `email`) | - (reuses challenges) |
| `sms` | Texted six-digit codes: login, signup, MFA; five ready-made gateway senders or bring-your-own `SmsSender` | user-phone entities (challenges shared with `email`) |
| `oauth` | OAuth2/OIDC: login, signup, linking, refresh; PKCE + validated id_tokens; runtime provider resolution | oauth token entities & lookups |
| `webauthn` | Passkeys: usernameless login, account-page registration | passkey blobs keyed by credential id |
| `totp` | Authenticator-app codes (RFC 6238) as a second factor, QR enrollment | one TOTP credential per user |
| `mfa` | Second-factor policy over any first factor | - (rides on `LoginMethod`) |
| `pages` | Bundled Askama pages + the `Pages` replacement trait | - |
| `axum` | The extractor, router and cookie layer | - |

Default: `user`, `email`, `password`, `oauth`.

## The store

Authery's only persistence interface is the
[`AutheryStore`](https://docs.rs/authery/latest/authery/store/trait.AutheryStore.html) trait. You implement it over your
database; authery never sees connection strings or SQL, and the trait
only asks for the methods your enabled features use. Each entity is a
trait your concrete types implement, with associated id types satisfying
[`Id`](https://docs.rs/authery/latest/authery/models/trait.Id.html) (`Clone + Display + FromStr + PartialEq + ...` - Uuid
works out of the box, and so do newtypes):

```rust
impl LoginSession for MySession {
    type Id = Uuid;
    type UserId = Uuid;
    fn get_id(&self) -> Uuid { self.id }
    fn get_user_id(&self) -> Uuid { self.user_id }
    fn get_method(&self) -> LoginMethod { self.method.clone() }
    fn get_expires(&self) -> DateTime<Utc> { self.expires }
}
```

Your types can carry any extra fields your app needs - authery only calls
the getters. A few store methods carry security-relevant contracts:

- `consume_challenge` must fetch **and delete** - challenges and codes
  are single-use.
- `create_session` ids act as bearer tokens: generate them with a CSPRNG
  (`Id::new_random` on Uuid does).
- `delete_session` / `delete_oauth_token` / `delete_passkey` are scoped
  by user id - verify ownership.

Because the store is your code, it observes every user creation, login
and token exchange - that's where app-level side effects (provisioning,
tenant membership, analytics) belong, without authery needing a hook for
each.

## Login methods

### Passwords (`password`)

[`PasswordConfig::new()`](https://docs.rs/authery/latest/authery/password/struct.PasswordConfig.html) gives argon2 hashing
on a blocking thread pool; swap the hasher with `.with_hasher(...)`.
Login is enumeration-resistant: unknown users and wrong passwords return
the same error, and comparable hash work is burned on the miss paths so
timing doesn't reveal account existence.

With `email` also enabled, password reset works over emailed links
(`.with_allow_reset(...)`, verified-only by default). Reset links create
single-use, purpose-bound sessions that cannot access anything but the
reset flow.

### Email links & one-time codes (`email`, `otp`)

Magic links for signup/login, address verification and password reset
delivery. SMTP is async (lettre) and configured with a single URL:

```text
smtps://user:pass@smtp.example.com:465                implicit TLS
smtp://user:pass@smtp.example.com:587?tls=required    STARTTLS
smtp://localhost:1025                                 plain, for Mailhog etc.
```

The `otp` feature sends one-time codes instead of links - same challenge
store, different UX. Codes are namespaced per address, single-use,
short-lived and rate-limited through your `RateLimiter`. The generator is
pluggable per channel (`CodeGenerator` via
`with_code_generator` on `EmailConfig`/`SmsConfig`); the default is
CSPRNG-backed six digits, and the bundled code-entry inputs adapt to a
custom generator through its input-mode and length hints. Remember that
any typeable code is guessable: the load-bearing control is the rate
limiter, not code length.

### OAuth2 & OIDC (`oauth`)

All authorization-code flows send PKCE (S256) and keep their state in
single-use encrypted cookies keyed per flow (concurrent login tabs don't
clobber each other). OIDC providers get full id_token validation:
signature against the issuer's JWKS, `iss`, `aud`, `exp` and a
per-request `nonce`. The validated claims are what your store receives.

Built-in providers, each a one-liner: GitHub, GitLab, Google, Spotify,
Microsoft, Discord, Facebook, Twitch, Slack, LinkedIn and X. For anything
else, `OAuthOidcProvider`
covers any spec-compliant OIDC issuer with full validation, and
`OAuthCustomProvider` covers plain OAuth2 with a callback that turns an
access token into a provider user.

Beyond login and signup, the `user` feature adds **linking** (attach
another provider to the logged-in account) and **refresh** (server-side,
ownership-checked token refresh). Access and refresh tokens live in your
store, so your app can use them for API integrations.

Every flow returns to a single callback route (default
`/oauth/callback`): the flow type, provider and PKCE/nonce material ride
the encrypted state cookie, so no per-provider or per-flow path segments
are needed. Register `{base_url}/oauth/callback` as the redirect URI with
each provider.

Providers don't have to be fixed at startup - see *Multi-tenancy* below.

### Passkeys (`webauthn`)

Two ceremonies wired end to end (JSON endpoints + inline page scripts):
registration from the account page (resident keys required) and
usernameless login - authery resolves the credential and user by
credential id, so your user-id type is never embedded in authenticator
hardware. Credentials are stored as opaque `Passkey` blobs; signature
counters and backup state are persisted after each login for clone
detection. Ceremony state rides the encrypted cookie jar, keyed per
ceremony.

### Authenticator apps (`totp`)

RFC 6238 codes (SHA-1, six digits, 30s steps, ±1 step skew - what
authenticator apps actually support). Enrollment is two-step so a typo'd
setup can't lock anyone out: `totp_enroll_start` returns an `otpauth://`
URL and a ready-to-embed QR PNG, and the secret only counts as a factor
after `totp_enroll_confirm` verifies a live code. Each successful
verification records the matched time step and rejects codes at or before
it - a captured code can't be replayed within its window.

### Texted codes (`sms`)

The email OTP flow for phone numbers: signup and login by texted
six-digit code, plus a texted second factor for MFA. Authery is
gateway-neutral: ready-made Twilio / Vonage / MessageBird / Telnyx /
46elks senders are included, and anything implementing the one-method
`SmsSender` trait works. Store numbers in E.164 form; authery compares
them as opaque strings. Mind the factor's limits: SIM-swap attacks are
routine enough that NIST discourages SMS for high-value accounts.

### Multi-factor authentication (`mfa`)

A policy layer over the other methods.
`MfaPolicy` names the first factors that must be backed
by a second one (default: passwords only). When such a login succeeds
*and the user has a factor registered*, the session is **pending** -
treated as logged-out everywhere except the completion flow, which offers
a passkey ceremony, an authenticator code, or a one-time code sent to the
user's **own verified** address or number (never one supplied in the
request, and never the channel the first factor already proved).
Completing it mints a session whose method records both factors.

Users without a registered factor log in normally - hard-requiring MFA at
login would lock out every fresh signup. Apps wanting mandatory MFA gate
their routes with `LoginMethodRules { require_mfa: true, .. }` instead
(single-factor passkeys count: possession + user verification).

## Sessions & bearer tokens

Sessions live in your store with CSPRNG ids, absolute expiry
(`with_session_lifetime`, default 30 days, server-side eviction) and an
optional per-user concurrency cap (`with_max_concurrent_sessions`, oldest
evicted first). Logout is POST-only.

For API and mobile clients, `.with_bearer_auth(true)` accepts
`Authorization: Bearer {token}` as an alternative to the session cookie
and exposes fresh session ids via an `X-Auth-Token` response header on
login. Tokens are opaque session ids - server-side, revocable, and
subject to the same expiry and caps as cookie sessions. There is
deliberately no stateless JWT mode. An optional
`.with_bearer_token_prefix("myapp_")` makes tokens recognizable to humans
and secret scanners, GitHub-`ghp_` style.

## Pages

The `pages` feature bundles plain Askama templates for login, signup, the
account page, password reset, code entry and the MFA picker. Restyle
them, or implement the `Pages` trait to render the same
view-models with your own templating - you keep the router and flows
while owning the markup. Or skip `pages` entirely and the router serves
only the action/callback endpoints.

## Routes

Every path authery serves or links to lives in the
[`Routes`](https://docs.rs/authery/latest/authery/routes/struct.Routes.html) struct handed to `AutheryConfig::new`, and all
of them are overridable - prefix everything, or reshape individual
routes with plain struct syntax:

```rust
// Everything under /auth:
let routes = Routes::default().with_prefix("/auth");

// ...or override specific paths:
let routes = Routes {
    oauth: OAuthRoutes {
        callback: "/auth/callback",
        ..Default::default()
    },
    pages: PageRoutes {
        login: "/signin",
        ..Default::default()
    },
    ..Default::default()
};
```

## Rate limiting

Authery calls your [`RateLimiter`](https://docs.rs/authery/latest/authery/ratelimit/trait.RateLimiter.html) before
abusable operations - password attempts, email/SMS sends, code
verification attempts - keyed on the identifier in question. IP-keyed
limiting is best done in a tower layer around the router; the hook covers
what only authery can see. Be strict on code attempts (six digits are
guessable) and SMS sends (every text costs money).

## Multi-tenancy

Authery deliberately has no organizations feature - members, roles,
invites and admin pages are app domain. What your app can't easily build
alone is the auth plumbing for per-tenant SSO against providers unknown
until request time, so that's the primitive authery provides:

1. Register an [`OAuthProviderResolver`](https://docs.rs/authery/latest/authery/oauth/trait.OAuthProviderResolver.html)
   that builds providers from *your* tables, keyed by an opaque context
   string (e.g. the tenant slug).
2. Start flows with `oauth_login_init_with_context(context, provider,
   next)` - the context rides the encrypted state cookie and both init
   and callback resolve through your resolver.
3. Your store receives the context alongside the **validated** claims on
   the resulting token - that's your membership hook.

The `memory-store` example contains a complete org setup built this way,
verified against Keycloak.

## Security

Argon2 off the async runtime; enumeration-resistant login; encrypted,
authenticated, `HttpOnly`, `SameSite=Lax` cookies (`Secure` unless
`.with_https_only(false)`; the encryption key is length-checked at config
time); PKCE everywhere; validated id_tokens; single-use, per-flow-keyed
state cookies; purpose-bound sessions that can't act as logins;
open-redirect protection on every `next` parameter.

Your side of the deal: serve over HTTPS, wire the rate limiter, treat the
cookie key as a secret, and honor the store contracts above.
`SECURITY_REVIEW.md` in the repo tracks the standing review, fixes and
known gaps.

## Local development

The repo ships a compose file with Keycloak (a real OIDC provider with a
preconfigured realm) and Mailhog (catches all outgoing email):

```sh
docker compose -f dev/compose.yaml up -d
# Mailhog UI:  http://localhost:8025
# Keycloak UI: http://localhost:8080 (admin/admin)
```

See `examples/memory-store` for a complete runnable app exercising every
feature, including the multi-tenant recipe.

Everything user-visible is exported through [`prelude`](https://docs.rs/authery/latest/authery/prelude/).

<!-- cargo-rdme end -->

## Development

```sh
docker compose -f dev/compose.yaml up -d   # Keycloak (OIDC) + Mailhog (SMTP)
cargo test --no-default-features \
  --features password,email,otp,mfa,user,totp,sms   # core flow tests
cargo test                                 # + live Keycloak OIDC validation when up
```

`dev/PROVIDERS.md` lists the external OAuth and SMS providers and the env
vars the example picks them up from. This README is generated from the crate
docs in `src/lib.rs` — edit there and run `cargo rdme` (CI checks the sync).

## License

[ISC](./license)

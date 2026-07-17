# Features & configuration

## Feature flags

| Feature | What it enables | Store additions |
|---|---|---|
| `user` | Account management: session listing, email/password management, account deletion | user-scoped queries & mutations |
| `password` | Password login/signup, pluggable hasher | password-id lookup & user creation |
| `email` | Magic links: login, signup, verification, password reset (with `password`); async SMTP | user-email entities, single-use challenges |
| `otp` | Six-digit emailed codes as an alternative to links (implies `email`) | — (reuses challenges) |
| `oauth` | OAuth2/OIDC: login, signup, linking, refresh; PKCE + validated id_tokens; runtime provider resolution | oauth token entities & lookups |
| `webauthn` | Passkeys: usernameless login, account-page registration | passkey blobs keyed by credential id |
| `totp` | Authenticator-app codes (RFC 6238) as a second factor, QR enrollment | one TOTP credential per user |
| `sms` | Texted six-digit codes: login, signup, MFA; bring-your-own `SmsSender` | user-phone entities (challenges shared with `email`) |
| `sms-providers` | Ready-made senders: Twilio, Vonage, MessageBird, Telnyx, 46elks (implies `sms`, pulls in an HTTP client) | — |
| `mfa` | Second-factor policy over any first factor (passkey, TOTP, emailed or texted code) | — (rides on `LoginMethod`) |
| `pages` | Bundled Askama pages + the `Pages` replacement trait | — |
| `axum` | The extractor, router and cookie layer | — |

Default: `user`, `email`, `password`, `oauth`.

## AutheryConfig

`AutheryConfig::new` takes the cookie-encryption key (min 64 bytes — it
returns an error otherwise, rather than panicking later), your `Routes`, and
one config per enabled method feature. Builder methods cover the rest:

```rust,ignore
AutheryConfig::new(key, Routes::default(), /* method configs */)?
    // Sessions expire absolutely; default 30 days.
    .with_session_lifetime(Duration::days(7))
    // Cap concurrent sessions per user; oldest are evicted on login.
    .with_max_concurrent_sessions(5)
    // Your rate limiter, consulted before abusable operations.
    .with_rate_limiter(MyLimiter::default())
    // Which first factors demand a second one (mfa feature).
    .with_mfa_policy(MfaPolicy { require_for_password: true, ..Default::default() })
    // Replace the bundled templates (pages feature).
    .with_pages(MyPages)
    // Accept `Authorization: Bearer {session_id}` and expose fresh session
    // ids via an `X-Auth-Token` response header — for API/mobile clients.
    .with_bearer_auth(true)
    // Local development only!
    .with_https_only(false)
```

## Bearer tokens

With `with_bearer_auth(true)`, clients that can't use cookies authenticate by
sending the session id back as `Authorization: Bearer {token}`; the token is
handed out in an `X-Auth-Token` response header whenever a login creates a
fresh session. Tokens are opaque server-side session ids — revocable via
logout/session deletion and subject to the same lifetime and concurrency caps
as cookie sessions. Nothing is signed client-side; there is no JWT to leak or
mis-validate.

## Routes

Every path authery serves or links to lives in the `Routes` struct — override
individual routes or prefix everything with `Routes::default().with_prefix("/auth")`.

## Rate limiting

Authery calls your [`RateLimiter`] before password attempts, email sends and
OTP verification attempts, keyed on the identifier in question. IP-keyed
limiting is best done in a tower layer around the router; the hook covers
what only authery can see — which operations are auth-sensitive:

```rust,ignore
impl RateLimiter for MyLimiter {
    fn check<'a>(&'a self, op: RateLimitOp<'a>) -> RateLimitFuture<'a> {
        Box::pin(async move {
            match op {
                RateLimitOp::PasswordAttempt { password_id } => { /* count, maybe Err(RateLimited)... */ }
                RateLimitOp::EmailSend { address } => { /* cap mail per recipient */ }
                RateLimitOp::OtpAttempt { address } => { /* six digits are guessable: be tight */ }
                RateLimitOp::SmsSend { number } => { /* every text costs money */ }
                _ => Ok(()), // TotpAttempt, SmsAttempt, future ops (non_exhaustive)
            }
        })
    }
}
```

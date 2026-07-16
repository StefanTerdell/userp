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
| `mfa` | Second-factor policy over any first factor (passkey or emailed code) | — (rides on `LoginMethod`) |
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
    // Local development only!
    .with_https_only(false)
```

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
                _ => Ok(()),
            }
        })
    }
}
```

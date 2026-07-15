# Security review (2026-07-15)

Full review of the userp workspace ahead of the authery revival work, per the
plan's phase 0. Scope: `userp-server`, `userp-axum-router`, `userp-pages`,
`userp-client`, plus the memory-store example as reference store impl.

## Sound foundations

- Password hashing via `password_auth` (argon2) on `spawn_blocking`.
- Session/state cookies live in an encrypted+authenticated `PrivateCookieJar`,
  `HttpOnly`, `SameSite=Lax`, `Secure` (configurable for local dev).
- Email challenge codes and session IDs are UUIDv4 (CSPRNG-backed), challenges
  are single-use (consumed on lookup) with a 5-minute default lifetime.
- OAuth callbacks validate the CSRF `state` against the cookie; flow data
  (including link/refresh target IDs) rides in the encrypted cookie, not in
  attacker-writable input.
- Askama templates auto-escape; no `|safe` usage.
- Store-side deletes (`delete_session`, `delete_oauth_token`) are scoped by
  user id.

## Fixed in this pass

| Finding                                                                                                                                       | Severity           | Fix                                                                                                                          |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `post_user_oauth_refresh` refreshed any token by id with no ownership check (IDOR)                                                            | High               | Token must belong to the logged-in user                                                                                      |
| Open redirect: user-supplied `next` passed to `Redirect::to` in password/email/oauth handlers                                                 | High               | `safe_next()` allows only local paths (`/…`, rejects `//`, `/\`, control chars)                                              |
| ID-token payload decoded with padded standard base64; JWTs are unpadded base64url, so parsing mostly failed                                   | High (correctness) | Decode with `URL_SAFE_NO_PAD`                                                                                                |
| No PKCE on the authorization-code flow (RFC 9700 requires it)                                                                                 | Medium             | S256 challenge on init, verifier stored in the encrypted state cookie, sent on exchange                                      |
| Password login enumeration: distinct "no user"/"wrong password" errors, and a timing oracle (no hash work for unknown users)                  | Medium             | Single "wrong email or password" error; comparable hash work burned on the miss paths                                        |
| Password-reset sessions survived the reset (link ≈ permanent session); `log_out` also skipped deleting them from the store                    | Medium             | `log_out` deletes whatever session the cookie names; reset handlers log out after setting the password                       |
| Any logged-in user could trigger verification mail for an arbitrary address, and enable link-login on unverified addresses (pre-hijack chain) | Medium             | `email_verify_init` requires the address to belong to the current user; link-login can only be enabled on verified addresses |
| OAuth state cookie survived the callback                                                                                                      | Low                | Removed on first use                                                                                                         |
| Unencoded email echoed into `Location` on the reset flow                                                                                      | Low                | URL-encoded                                                                                                                  |

## Hardened during the rewrite (post-phase-1)

These were flagged as deferred and have since been fixed on the `authery` crate:

| Finding                                                    | Fix                                                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sessions never expired (unbounded `LoginSession` lifetime) | Absolute expiry: configurable `session_lifetime` (default 30 days), `LoginSession::is_expired()`, and the core evicts expired sessions from the store on next use (login + reset paths)                                                                                                                                                         |
| ID-token signature/nonce/aud/iss not validated             | `validate_oidc_id_token` verifies the JWT signature against the provider's JWKS (discovered from the issuer) and checks `iss`/`aud`/`exp`; a per-request `nonce` is added to the auth URL, stored in the encrypted state cookie, and matched against the id_token. Covered by an integration test against Keycloak (`tests/oidc_validation.rs`) |
| Logout was a GET (CSRF-able)                               | Logout route is now POST-only (verified: GET → 405)                                                                                                                                                                                                                                                                                             |
| `Key::from` panicked on short cookie keys                  | `AutheryConfig::new` returns `Err(AutheryConfigError::KeyTooShort)` for keys under 64 bytes                                                                                                                                                                                                                                                     |

## Known gaps still open

- **No rate limiting / lockout** on password guesses or email-challenge sends
  (the latter is a mail-spam vector). Best handled as a tower layer at the app
  level (e.g. `tower_governor`) since the built-in router composes with
  `.layer(...)`; document as app responsibility, optionally add hooks later.
- **Logging in doesn't cap concurrent sessions** and re-login orphans the old
  session server-side.
- **SMTP send is synchronous** (`lettre::SmtpTransport`) inside async handlers.
- Test coverage is thin: OIDC id_token validation has an integration test; the
  password/email/session flows are exercised manually (curl against the
  memory-store example) but not yet in an automated suite.

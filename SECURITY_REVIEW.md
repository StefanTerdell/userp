# Security review (2026-07-15, updated 2026-08-27)

Full review of the codebase authery inherited from its predecessor crate
(`userp`), done ahead of the rewrite. Scope at the time: the `userp-server`,
`userp-axum-router`, `userp-pages` and `userp-client` crates plus the
memory-store example as reference store impl - all since folded into the single
`authery` crate. Findings and their fixes carry over; the bottom section tracks
what has been closed since.

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
| Cookie removal never took in the browser: removal cookies were sent without the `Path=/` the originals carry, so "single-use" state cookies survived their use client-side (masked by the IdP rejecting reused codes) | `AutheryCookies::remove` now builds the removal cookie with the same attributes as `add`; verified live — replaying an OAuth callback now fails at the missing-cookie check rather than reaching the code exchange (2026-07-17)                                                                                                                  |
| OAuth flow state lived in a single cookie slot, so two concurrent flows (two login tabs, or login + link) clobbered each other and the older flow failed with a CSRF mismatch | The flow cookie is keyed by the CSRF state (`authery-oauth-state-{state}`); the callback selects the cookie by the state query param. Verified live against Keycloak: two interleaved flows both complete (2026-07-17)                                                                                                                          |
| Same single-slot pattern on the three WebAuthn ceremony cookies (login, registration, MFA factor) | Ceremony cookies are keyed by the challenge; the finish call recovers the key from the challenge echoed in `clientDataJSON` (which only *selects* the cookie — the signed ceremony validation still runs against the encrypted state). Verified with headless Chrome + a CDP virtual authenticator: two interleaved login ceremonies both complete (2026-07-17) |

## Closed since the review

- **Rate limiting hook** (`authery::ratelimit::RateLimiter`): authery calls
  the app-supplied limiter before password attempts, code/TOTP/recovery
  verification, and email/SMS sends, keyed on the relevant identifier. No
  limiter implementation ships (backing store and IP keying are app
  decisions); `examples/full/src/ratelimit.rs` shows an in-memory one.
- **Concurrent-session cap** (`max_concurrent_sessions`): oldest sessions are
  evicted server-side on login once the cap is hit. Idle timeout
  (`idle_timeout`) and cookie-key rotation grace were added alongside.
- **Async SMTP**: `lettre::AsyncSmtpTransport` on the tokio executor.
- **Automated tests**: `tests/flows.rs` covers the password, email link/code,
  SMS, TOTP, recovery-code and MFA-policy flows against an in-memory store;
  `tests/oidc_validation.rs` covers id_token validation against Keycloak;
  `dev/e2e` drives the WebAuthn browser ceremonies through a headless-Chrome
  virtual authenticator. The OAuth flows are exercised manually against the
  Keycloak in `dev/compose.yaml`.

## Known gaps still open

- **No built-in lockout**: the rate-limit hook exists, but the crate itself
  never refuses a request unless the app plugs a limiter in. Documented as an
  app responsibility.
- **Dependency advisory**: `rsa` (via `jsonwebtoken`) carries RUSTSEC-2023-0071
  (Marvin timing attack on PKCS#1 v1.5 *decryption*). Authery only uses RSA to
  verify id_token signatures, so the affected path is not reachable; tracked as
  an explicit ignore in `deny.toml` until an upstream fix lands.

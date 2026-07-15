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

| Finding | Severity | Fix |
|---|---|---|
| `post_user_oauth_refresh` refreshed any token by id with no ownership check (IDOR) | High | Token must belong to the logged-in user |
| Open redirect: user-supplied `next` passed to `Redirect::to` in password/email/oauth handlers | High | `safe_next()` allows only local paths (`/…`, rejects `//`, `/\`, control chars) |
| ID-token payload decoded with padded standard base64; JWTs are unpadded base64url, so parsing mostly failed | High (correctness) | Decode with `URL_SAFE_NO_PAD` |
| No PKCE on the authorization-code flow (RFC 9700 requires it) | Medium | S256 challenge on init, verifier stored in the encrypted state cookie, sent on exchange |
| Password login enumeration: distinct "no user"/"wrong password" errors, and a timing oracle (no hash work for unknown users) | Medium | Single "wrong email or password" error; comparable hash work burned on the miss paths |
| Password-reset sessions survived the reset (link ≈ permanent session); `log_out` also skipped deleting them from the store | Medium | `log_out` deletes whatever session the cookie names; reset handlers log out after setting the password |
| Any logged-in user could trigger verification mail for an arbitrary address, and enable link-login on unverified addresses (pre-hijack chain) | Medium | `email_verify_init` requires the address to belong to the current user; link-login can only be enabled on verified addresses |
| OAuth state cookie survived the callback | Low | Removed on first use |
| Unencoded email echoed into `Location` on the reset flow | Low | URL-encoded |

## Known gaps, deferred to the rewrite (phases 1+)

- **Sessions never expire.** The `LoginSession` trait has no expiry; lifetime
  is unbounded. Needs an expiry column + renewal semantics in the new trait
  design.
- **ID-token signature/nonce/aud/iss are not validated.** Tolerable for the
  code flow (token comes straight from the token endpoint over TLS, per OIDC
  Core 3.1.3.7) and flagged with a warning on the type, but proper JWKS
  validation + nonce should land with the new OIDC client.
- **No rate limiting / lockout** on password guesses or email-challenge sends
  (the latter is a mail-spam vector). Document as app responsibility or add
  hooks.
- **Logout is a GET** — CSRF-able (nuisance-level). Consider POST in the new
  router.
- **`Key::from(config.key.as_bytes())` panics** on keys shorter than 64 bytes;
  should be a constructor error instead.
- **Logging in doesn't cap concurrent sessions** and re-login orphans the old
  session server-side.
- **SMTP send is synchronous** (`lettre::SmtpTransport`) inside async handlers.
- No test suite; the rewrite should carry security regression tests for the
  items above.

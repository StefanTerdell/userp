# Security notes

What authery does for you:

- Argon2 password hashing off the async runtime; enumeration-resistant login
  (identical errors + comparable timing for unknown users).
- Encrypted, authenticated, `HttpOnly`, `SameSite=Lax` cookies (`Secure`
  unless `.with_https_only(false)`); the encryption key must be ≥ 64 bytes
  and is validated at config time.
- Sessions: CSPRNG ids, absolute expiry with server-side eviction, POST-only
  logout, optional concurrent-session caps. Purpose-bound sessions (password
  reset, pending MFA) cannot act as logins.
- OAuth: PKCE everywhere, single-use encrypted state, OIDC id_token
  validation (JWKS signature, iss/aud/exp/nonce), refresh/link ownership
  checks.
- Email challenges and OTP codes: single-use, expiring, address-namespaced.
- Open-redirect protection on every `next` parameter.

What stays your responsibility:

- **Rate limiting**: wire the `RateLimiter` hook (identifier-keyed) and put
  an IP-keyed tower layer in front of the router. Be strict on
  `OtpAttempt`.
- **Serve over HTTPS** and keep `https_only` on outside development.
- **Key management**: the cookie key is a secret; rotate it and sessions
  drop.
- **Store contracts**: single-use challenge consumption, ownership-scoped
  deletes (see [the store chapter](store.md)).
- **Authorization**: authery authenticates; what a user may do is app logic.

`SECURITY_REVIEW.md` in the repo tracks the standing review, fixes and known
gaps.

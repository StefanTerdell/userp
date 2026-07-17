# Authenticator apps (TOTP)

The `totp` feature adds RFC 6238 time-based one-time passwords — the codes
from Google Authenticator, 1Password, and friends — as a second factor.
Configure it with the issuer name your users should see in their app:

```rust,ignore
TotpConfig::new("My App")
```

Codes are SHA-1, six digits, 30-second steps, with one step of clock skew
accepted in each direction — the parameters every authenticator app actually
supports.

## Enrollment

Enrollment is two-step so a typo'd setup can never lock anyone out:

1. `totp_enroll_start(account_label)` generates a secret and returns a
   `TotpEnrollment` with the `otpauth://` URL and a ready-to-embed QR PNG
   (base64). The secret is stored **unconfirmed** and does not count as a
   factor yet.
2. `totp_enroll_confirm(code)` verifies a code from the user's app and marks
   the secret confirmed.

The built-in account page has an "Authenticator" tab driving both steps, plus
disable. The store persists a single `TotpCredential` per user
(`get_totp`/`upsert_totp`/`delete_totp`).

## Verification & replay protection

At login, a confirmed TOTP credential shows up as an MFA factor next to
passkeys and emailed/texted codes. Each successful verification records the
**matched time step**, and any code at or before that step is rejected — a
captured code can't be replayed within its 30-second window, while the next
step's code stays valid even inside the same wall-clock window.

Attempts are rate-limited per user through your `RateLimiter`
(`RateLimitOp::TotpAttempt`).

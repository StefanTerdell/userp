# Email links & one-time codes

The `email` feature covers signup/login links ("magic links"), address
verification and password reset delivery. Challenges are stored via your
store, single-use, and expire (default 5 minutes,
`EmailConfig::with_challenge_lifetime`).

SMTP is async (lettre) and configured with a single URL:

```text
smtps://user:pass@smtp.example.com:465          implicit TLS
smtp://user:pass@smtp.example.com:587?tls=required   STARTTLS
smtp://localhost:1025                            plain, for Mailhog etc.
```

## One-time codes (`otp`)

The `otp` feature sends six-digit codes instead of links — same challenge
store, different UX. Codes are:

- generated from a CSPRNG,
- namespaced per address (a code issued for one address never verifies for
  another),
- single-use and short-lived,
- rate-limited per address through your `RateLimiter`
  (`RateLimitOp::OtpAttempt`) — configure this tightly, six digits are
  guessable.

The built-in pages add "email me a code" to login/signup and a code-entry
page; one route serves both steps (POST without `code` sends, with `code`
verifies).

# Phone codes (SMS)

The `sms` feature mirrors the email one-time-code flow for phone numbers:
signup and login by texted six-digit code, and a texted-code second factor
for MFA. Authery is gateway-neutral — you hand `SmsConfig` anything that
implements the two-method `SmsSender` trait:

```rust,ignore
struct MySender;

impl SmsSender for MySender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a> {
        Box::pin(async move { /* call your gateway */ Ok(()) })
    }
}

SmsConfig::new(MySender)
```

## Ready-made senders (`sms-providers`)

The `sms-providers` feature (pulls in an HTTP client) ships thin senders for
popular gateways, all exported from the prelude:

| Sender | Service |
|--------|---------|
| `TwilioSmsSender` | Twilio |
| `VonageSmsSender` | Vonage (Nexmo) |
| `MessageBirdSmsSender` | MessageBird |
| `TelnyxSmsSender` | Telnyx |
| `FortySixElksSmsSender` | 46elks |

Each takes its credentials and sender id as constructor args, e.g.
`TwilioSmsSender::new(account_sid, auth_token, from)`.

## Store & model

Your store gains a `UserPhone` model (number, verified, allow-login flags)
and three methods: `sms_get_user_by_phone`, `sms_create_user_by_phone`, and
`get_user_phones`. Store numbers in E.164 form (`+46701234567`) — authery
compares them as opaque strings. Challenges reuse the email challenge store
with namespaced keys, so enabling `sms` without `email` still only requires
the two challenge methods.

Codes are CSPRNG-generated, namespaced per number, single-use, short-lived
(default 5 minutes, `with_challenge_lifetime`), and rate-limited through your
`RateLimiter` (`RateLimitOp::SmsSend` / `SmsAttempt`) — limit these tightly:
six digits are guessable and every send costs you money.

## As a second factor

A **verified** phone number makes the user MFA-capable: pending logins can
have a code texted to the user's own number (never one supplied in the
request) and verify it to complete the login. Texted codes are not offered
when the first factor was itself an SMS code. `MfaPolicy::require_for_sms`
(default `false`) controls whether SMS *first*-factor logins demand a second
factor.

Be aware of SMS's limits as a factor — SIM-swap attacks are routine enough
that NIST discourages SMS for high-value accounts. Prefer TOTP or passkeys
where you can; SMS remains far better than nothing.
